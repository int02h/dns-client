package com.dpforge.dns.client.util

class ByteArrayBuilder {
    private val bytes = mutableListOf<Byte>()

    fun addByte(value: Byte): ByteArrayBuilder {
        return addByte(value.toInt() and 0xFF)
    }

    fun addByte(value: Int): ByteArrayBuilder {
        if (value.shr(8) != 0) {
            error("Bad byte: $value")
        }
        bytes += value.toByte()
        return this
    }

    fun addShort(value: Short): ByteArrayBuilder {
        return addShort(value.toInt() and 0xFFFF)
    }

    fun addShort(value: Int): ByteArrayBuilder {
        if (value.shr(16) != 0) {
            error("Bad short: $value")
        }
        addByte(value.shr(8))
        addByte(value and 0xFF)
        return this
    }

    fun addBytes(value: ByteArray): ByteArrayBuilder {
        value.forEach(::addByte)
        return this
    }

    fun toByteArray(): ByteArray = bytes.toByteArray()
}