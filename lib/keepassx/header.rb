# frozen_string_literal: true
require 'pry'
# The keepass file header.
module Keepassx
  class Header
    FILE_VERSION_MASK = 0xFFFF0000
    SIGNATURES = [0x9AA2D903, 0xB54BFB67].freeze

    AES_CIPHER_UUID = "\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF".b.freeze
    TWOFISH_CIPHER_UUID = "\xAD\x68\xF2\x9F\x57\x66\x4B\xB9\xA3\x6C\xD4\x7E\xF0\xFD\xFB\xAE".b.freeze
    TWOFISH_ALT_CIPHER_UUID = "\xAD\x68\xF2\x9F\x57\x6F\x4B\xB9\xA3\x6A\xD4\x7A\xF9\x65\x34\x6C".b.freeze
    CHACHA20_CIPHER_UUID = "\xD6\x03\x8A\x2B\x8B\x6F\x4C\xB5\xA5\x24\x33\x9A\x31\xDB\xB5\x9A".b.freeze

    CIPHER_UUIDS = {
      AES_CIPHER_UUID         => "AES",
      TWOFISH_CIPHER_UUID     => "TwoFish",
      TWOFISH_ALT_CIPHER_UUID => "TwoFish",
      CHACHA20_CIPHER_UUID    => "ChaCha20",
    }.freeze

    KDF_UUIDS = {
      0xC9D9      => "aes",
      0xEF63      => "argon2d",
      0x9E29      => "argon2id",
      "aes"       => 0xC9D9,
      "argon2d"   => 0xEF63,
      "argon2id"  => 0x9E29,
    }.freeze

    PACK_CODES = {
      'Bool'      => 'C',
      'Bytes'     => 'n*',
      'HexString' => 'H*',
      'Int32'     => 'l<',
      'Int64'     => 'q<',
      'String'    => 'U*',
      'UInt8'     => 'C',
      'UInt16'    => 'S<',
      'UInt32'    => 'L<',
      'UInt64'    => 'Q<',
      0x04        => 'L<',
      0x05        => 'Q<',
      0x08        => 'C',
      0x0C        => 'l<',
      0x0D        => 'q<',
      0x18        => 'U*',
      0x42        => 'n*',
    }.freeze

    attr_reader   :encryption_iv
    attr_reader   :encryption_type
    attr_accessor :groups_count
    attr_accessor :entries_count
    attr_accessor :content_hash
    attr_accessor :total_bytes_read

    # rubocop:disable Metrics/MethodLength
    def initialize(db = nil)
      @total_bytes_read = 0
      return init_new_header if db.nil?

      db_stream = StringIO.new(db)
      @signature1 = db_stream.read(4).unpack1(PACK_CODES['UInt32'])
      @signature2 = db_stream.read(4).unpack1(PACK_CODES['UInt32'])

      unless valid?
        raise "Invalid header signatures: #{@signature1}, #{@signature2}"
      end

      @version = db_stream.read(4).unpack1(PACK_CODES['UInt32'])
      @kdbx_version = (@version & FILE_VERSION_MASK) >> 16

      @total_bytes_read += 12

      case @kdbx_version
      when 3..4
        read_header_fields(db_stream)
      else
        raise "Unsupported KDBX version: #{@kdbx_version}"
      end
    end

    def valid?
      @signature1 == SIGNATURES[0] && @signature2 == SIGNATURES[1]
    end

    # rubocop:disable Metrics/MethodLength
    def final_key(master_key, keyfile_data = nil)
      key = Digest::SHA2.new.update(master_key).digest

      if keyfile_data
        keyfile_hash = extract_keyfile_hash(keyfile_data)
        key = master_key == '' ? keyfile_hash : Digest::SHA2.new.update(key + keyfile_hash).digest
      end

      # If we got this far without @kdf_parameters set, we should be on a v3
      # database with the aes KDF.
      if @kdf_parameters.nil? or @kdf_parameters.size == 0
        @kdf_parameters = { }
        @kdf_parameters['$UUID'] = KDF_UUIDS["aes"]
        @kdf_parameters['R'] = @rounds
      end

      @rounds ||= @kdf_parameters['R']
      @master_seed2 ||= @kdf_parameters['S']

      aes = OpenSSL::Cipher.new('AES-256-ECB')
      aes.encrypt
      aes.key = @master_seed2
      aes.padding = 0

      @rounds.times do
        key = aes.update(key) + aes.final
      end

      key = Digest::SHA2.new.update(key).digest
      key = Digest::SHA2.new.update(@master_seed + key).digest
      key
    end
    # rubocop:enable Metrics/MethodLength


    # Return encoded header
    #
    # @return [String] Encoded header representation.
    def encode
      self.send("encode_v#{@kdbx_version}_header")
    end


    private

      def init_new_header()
        @signature1    = SIGNATURES[0]
        @signature2    = SIGNATURES[1]
        @flags         = 3 # SHA2 hashing, AES encryption
        @version       = 0x40000
        @master_seed   = SecureRandom.random_bytes(16)
        @encryption_iv = SecureRandom.random_bytes(16)
        @groups_count  = 0
        @entries_count = 0
        @master_seed2  = SecureRandom.random_bytes(32)
        @rounds        = 50_000
      end

      def read_header_fields(header_bytes)
        field_id = nil
        field_size = 0

        while field_id != 0x00
          f = header_bytes.read(1)
          break if f.nil?
          @total_bytes_read += 1
          field_id = f.unpack1(PACK_CODES['UInt8'])
          break if field_id == 0x00
          field_size_width = @kdbx_version == 4 ? 4 : 2
          field_size_pack_code = PACK_CODES["UInt#{field_size_width * 8}"]
          field_size = header_bytes.read(field_size_width).unpack1(field_size_pack_code)
          @total_bytes_read += field_size_width

          binding.pry
          case field_id
          when 0x01 # Comment
            @comment = header_bytes.read(field_size)
          when 0x02 # Cipher ID
            @cipher_uuid = header_bytes.read(field_size)
            @encryption_type = CIPHER_UUIDS[@cipher_uuid]
            if @encryption_type.nil?
              raise "Unsupported cipher: #{@cipher_uuid.unpack1(PACK_CODES['HexString'])}"
            end
          when 0x03 # Compression flags
            @compression_flag = header_bytes.read(field_size).unpack1(PACK_CODES['UInt16'])
            # Compression flag handling if needed
          when 0x04 # Master seed
            @master_seed = header_bytes.read(field_size)
          when 0x05 # Transform seed
            @master_seed2 = header_bytes.read(field_size)
          when 0x06 # Transform rounds
            @rounds = header_bytes.read(field_size).unpack1(PACK_CODES['UInt64'])
          when 0x07 # Encryption IV
            @encryption_iv = header_bytes.read(field_size)
          when 0x08 # Protected Stream Key
            @protected_stream_key = header_bytes.read(field_size)
          when 0x09 # Stream start bytes
            @stream_start_bytes = header_bytes.read(field_size)
          when 0x0A # Inner Random Stream ID
            @inner_random_stream_id = header_bytes.read(field_size).unpack1(PACK_CODES['UInt16'])
            # Inner Random Stream ID handling if needed
          when 0x0B # KDF parameters
            kdf_parameters_raw = header_bytes.read(field_size)
            @kdf_parameters = parse_kdf_parameters(kdf_parameters_raw)
            @kdf_name = KDF_UUIDS[@kdf_parameters['$UUID']]
            if @kdf_name.nil?
              raise "unsupported KDF UUID: #{@kdf_parameters['$UUID']}"
            end
          when 0x0C # Public Custom data
            @public_custom_data = header_bytes.read(field_size)
          else
            header_bytes.read(field_size) # Skip unknown field data
          end

          @total_bytes_read += field_size
        end
      end

      def parse_kdf_parameters(kdf_parameters_raw)
        kdf_parameters = {}
        kdf_parameters_buffer = StringIO.new(kdf_parameters_raw)

        # A VariantDictionary is a key-value dictionary (with the key being a
        # string and the value being an object), which is serialized as follows:
        #
        # [2 bytes] Version, as UInt16, little-endian, currently 0x0100 (version 1.0).
        # The high byte is critical (i.e. the loading code should refuse to load the
        # data if the high byte is too high), the low byte is informational (i.e.
        # it can be ignored).
        #
        # [n items] n serialized items (see below).
        #
        # [1 byte] Null terminator byte.
        #
        @variant_map_version = kdf_parameters_buffer.read(2)
        @total_bytes_read += 2

        # Each of the n serialized items has the following form:
        # [1 byte] Value type, can be one of the following:
        # 0x04: UInt32.
        # 0x05: UInt64.
        # 0x08: Bool.
        # 0x0C: Int32.
        # 0x0D: Int64.
        # 0x18: String (UTF-8, without BOM, without null terminator).
        # 0x42: Byte array.
        #
        # [4 bytes] Length k of the key name in bytes, Int32, little-endian.
        #
        # [k bytes] Key name (string, UTF-8, without BOM, without null terminator).
        #
        # [4 bytes] Length v of the value in bytes, Int32, little-endian.
        #
        # [v bytes] Value. Integers are stored in little-endian encoding, and a
        # Bool is one byte (false = 0, true = 1); the other types are clear.
        #
        while kdf_parameters_buffer.pos < kdf_parameters_buffer.length
          kdf_param_type = kdf_parameters_buffer.read(1).unpack1(PACK_CODES['UInt8'])
          @total_bytes_read += 1
          break if kdf_param_type == 0x00

          # [4 bytes] Length k of the key name in bytes, Int32, little-endian.
          kdf_param_key_size = kdf_parameters_buffer.read(4).unpack1(PACK_CODES['Int32'])
          @total_bytes_read += 4

          # [k bytes] Key name (string, UTF-8, without BOM, without null terminator).
          kdf_param_key = kdf_parameters_buffer.read(kdf_param_key_size).force_encoding('UTF-8')
          @total_bytes_read += kdf_param_key_size

          # [4 bytes] Length v of the value in bytes, Int32, little-endian.
          kdf_param_value_size = kdf_parameters_buffer.read(4).unpack1(PACK_CODES['Int32'])
          @total_bytes_read += 4

          # [v bytes] Value. Integers are stored in little-endian encoding, and a
          # Bool is one byte (false = 0, true = 1); the other types are clear.
          value_unpack_code = PACK_CODES[kdf_param_type]
          kdf_param_value = kdf_parameters_buffer.read(kdf_param_value_size).unpack1(value_unpack_code)
          @total_bytes_read += kdf_param_value_size

          # Coax Bool into Ruby true/false
          if value_unpack_code == PACK_CODES['Bool']
            kdf_param_value = kdf_param_value == 1 ? true : false
          end

          kdf_parameters[kdf_param_key] = kdf_param_value
        end

        kdf_parameters
      end

      def kdf_aes(kdf_parameters)
        puts "KDF AES CALLED WITH #{kdf_parameters.inspect}"
      end

      def kdf_argon2id(kdf_parameters)
        puts "KDF ARGON2ID CALLED WITH #{kdf_parameters.inspect}"
      end

      def kdf_argon2d(kdf_parameters)
        puts "KDF ARGON2D CALLED WITH #{kdf_parameters.inspect}"
      end

      def extract_keyfile_hash(keyfile_data)
        # Hex encoded key
        if keyfile_data.size == 64
          [keyfile_data].pack(PACK_CODES['HexString'])

        # Raw key
        elsif keyfile_data.size == 32
          keyfile_data

        else
          Digest::SHA2.new.update(keyfile_data).digest
        end
      end

  end
end
