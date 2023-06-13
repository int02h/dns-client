package com.dpforge.dns.client.message

import java.nio.ByteBuffer
import com.dpforge.dns.client.message.ResourceRecord.Class
import com.dpforge.dns.client.message.ResourceRecord.Data
import com.dpforge.dns.client.message.ResourceRecord.Type

class MessageDecoder {
    fun decode(data: ByteArray): Message {
        val buffer = ByteBuffer.wrap(data)
        val id = buffer.getShort()
        val flags = buffer.getShort().toInt()
        val questionCount = buffer.getShort()
        val answerCount = buffer.getShort()
        val nameServerCount = buffer.getShort()
        val additionalRecordCount = buffer.getShort()

        val questions = decodeQuestions(buffer, questionCount)
        val answers = decodeResourceRecords(buffer, answerCount)
        val nameServers = decodeResourceRecords(buffer, nameServerCount)
        val additionalRecords = decodeResourceRecords(buffer, additionalRecordCount)

        return Message(
            id = id,
            qr = Message.QR.values()[flags.bitInt(15)],
            opcode = Message.Opcode.values()[flags.shr(11) and 0xF],
            authoritativeAnswer = flags.bit(10),
            truncation = flags.bit(9),
            recursionDesired = flags.bit(8),
            recursionAvailable = flags.bit(7),
            responseCode = Message.ResponseCode.values()[flags and 0xF],
            questions = questions,
            answers = answers,
            nameServers = nameServers,
            additionalRecords = additionalRecords
        )
    }

    private fun decodeQuestions(buffer: ByteBuffer, count: Short): List<Question> {
        return (0 until count).map {
            Question(
                name = decodeCompressedName(buffer),
                type = Type.getByValue(buffer.getShort()),
                clazz = Class.getByValue(buffer.getShort())
            )
        }
    }

    private fun decodeResourceRecords(buffer: ByteBuffer, count: Short): List<ResourceRecord> {
        return (0 until count).map {
            val name = decodeCompressedName(buffer)
            val type = Type.getByValue(buffer.getShort())
            val clazz = Class.getByValue(buffer.getShort())
            val ttl = buffer.getInt().toLong() and 0xFFFF_FFFF
            val dataLength = buffer.getShort().toInt() and 0xFFFF
            val endPosition = buffer.position() + dataLength
            val data = when (type) {
                Type.A -> Data.A(ByteArray(dataLength).also(buffer::get))
                Type.NS -> Data.NS(decodeCompressedName(buffer))
                Type.MD -> Data.MD(decodeCompressedName(buffer))
                Type.MF -> Data.MF(decodeCompressedName(buffer))
                Type.CNAME -> Data.CNAME(decodeCompressedName(buffer))
                Type.SOA -> Data.SOA(
                    dataSourceDomainName = decodeCompressedName(buffer),
                    mailboxDomainName = decodeCompressedName(buffer),
                    serial = buffer.getInt().toLong() and 0xFFFF_FFFF,
                    refresh = buffer.getInt().toLong() and 0xFFFF_FFFF,
                    retry = buffer.getInt().toLong() and 0xFFFF_FFFF,
                    expire = buffer.getInt().toLong() and 0xFFFF_FFFF,
                    minimum = buffer.getInt().toLong() and 0xFFFF_FFFF,
                )
                Type.MB -> Data.MB(decodeCompressedName(buffer))
                Type.MG -> Data.MG(decodeCompressedName(buffer))
                Type.MR -> Data.MR(decodeCompressedName(buffer))
                Type.NULL -> Data.NULL(rawData = ByteArray(dataLength).also(buffer::get))
                Type.WKS -> Data.WKS(
                    rawIP = ByteArray(dataLength).also(buffer::get),
                    protocol = buffer.get().toInt() and 0xFF,
                    bitMap = ByteArray(dataLength - 5).also(buffer::get)
                )
                Type.PTR -> Data.PTR(name = decodeCompressedName(buffer))
                Type.HINFO -> Data.HINFO(
                    cpu = decodeCharacterString(buffer),
                    os = decodeCharacterString(buffer)
                )
                Type.MINFO -> Data.MINFO(
                    rMailBox = decodeCompressedName(buffer),
                    eMailBox = decodeCompressedName(buffer)
                )
                Type.MX -> Data.MX(
                    preference = buffer.getShort().toInt() and 0xFF,
                    exchange = decodeCompressedName(buffer)
                )
                Type.TXT -> {
                    val texts = mutableListOf<String>()
                    while (buffer.position() < endPosition) {
                        texts += decodeCharacterString(buffer)
                    }
                    Data.TXT(texts)
                }

                // Additional RFCs
                Type.AAAA -> Data.AAAA(ByteArray(dataLength).also(buffer::get))
                Type.SRV -> Data.SRV(
                    priority = buffer.getShort().toInt() and 0xFFFF,
                    weight = buffer.getShort().toInt() and 0xFFFF,
                    port = buffer.getShort().toInt() and 0xFFFF,
                    target = decodeCompressedName(buffer),
                )
                Type.HTTPS -> {
                    val svcPriority = buffer.getShort().toInt() and 0xFF
                    val targetName = decodeCompressedName(buffer)
                    val params = mutableListOf<Pair<Int, String>>()
                    while (buffer.position() < endPosition) {
                        val key = buffer.getShort().toInt() and 0xFF
                        val valueLength = buffer.getShort().toInt() and 0xFF
                        val value = ByteArray(valueLength).also(buffer::get).toString(Charsets.US_ASCII)
                        params += key to value
                    }
                    Data.HTTPS(svcPriority, targetName, params)
                }
                Type.CAA -> {
                    val flags = buffer.get().toInt() and 0xFF
                    val tagLength = buffer.get().toInt() and 0xFF
                    val tag = ByteArray(tagLength).also(buffer::get).toString(Charsets.US_ASCII)
                    val valueLength = dataLength - tagLength - 2
                    val value = ByteArray(valueLength).also(buffer::get)
                    Data.CAA(flags, tag, value)
                }

                // QType
                Type.AXFR,
                Type.MAILB,
                Type.MAILA,
                Type.ALL -> error("QType is not expected")
            }
            if (buffer.position() != endPosition) {
                error(
                    "RData was not read correctly. " +
                            "Expected buffer position: $endPosition; actual position: ${buffer.position()}; " +
                            "Type: $type"
                )
            }
            ResourceRecord(name = name, type = type, clazz = clazz, ttl = ttl, data = data)
        }
    }

    private fun decodeCompressedName(buffer: ByteBuffer): String {
        val labelData = ByteArray(64)
        val result = StringBuilder()

        var returnPosition = -1
        while (true) {
            val length = buffer.get().toInt() and 0xFF
            if (length.bit(6) and length.bit(7)) { // compression
                val offset = (length and 0x3F).shl(8) + (buffer.get().toInt() and 0xFF)
                if (returnPosition == -1) {
                    returnPosition = buffer.position()
                }
                buffer.position(offset)
                continue
            } else if (length == 0) {
                break
            }
            buffer.get(labelData, 0, length)
            if (result.isNotEmpty()) {
                result.append('.')
            }
            result.append(String(labelData, 0, length, Charsets.US_ASCII))
        }
        if (returnPosition > -1) {
            buffer.position(returnPosition)
        }
        return result.toString()
    }

    private fun decodeCharacterString(buffer: ByteBuffer): String {
        val length = buffer.get().toInt() and 0xFF
        return ByteArray(length).also(buffer::get).toString(Charsets.US_ASCII)
    }

    private fun Int.bit(index: Int): Boolean = (this shr index) and 0b1 > 0
    private fun Int.bitInt(index: Int): Int = (this shr index) and 0b1
}