package com.dpforge.dns.client.message

import com.dpforge.dns.client.util.ByteArrayBuilder

class MessageEncoder {
    fun encode(message: Message): ByteArray {
        val builder = ByteArrayBuilder()
        encodeHeader(builder, message)
        encodeQuestions(builder, message.questions)
        return builder.toByteArray()
    }

    private fun encodeHeader(builder: ByteArrayBuilder, message: Message) {
        builder.addShort(message.id)
        builder.addByte(
            message.qr.ordinal.shl(7) +
                    message.opcode.ordinal.shl(3) +
                    message.authoritativeAnswer.asInt().shl(2) +
                    message.truncation.asInt().shl(1) +
                    message.recursionDesired.asInt()
        )
        builder.addByte(message.recursionAvailable.asInt().shl(7) + message.responseCode.ordinal)
        builder.addShort(message.questions.size)

        if (message.answers.isNotEmpty()) {
            error("Encoding answers is not supported")
        }
        builder.addShort(0)

        if (message.nameServers.isNotEmpty()) {
            error("Encoding name servers is not supported")
        }
        builder.addShort(0)

        if (message.additionalRecords.isNotEmpty()) {
            error("Encoding additional records is not supported")
        }
        builder.addShort(0)
    }

    private fun encodeQuestions(builder: ByteArrayBuilder, questions: List<Question>) {
        questions.forEach { q ->
            val labels = q.name.split('.')
            labels.forEach { l -> encodeLabel(builder, l) }
            builder.addByte(0)
            builder.addShort(q.type.value)
            builder.addShort(q.clazz.value)
        }
    }

    private fun encodeLabel(builder: ByteArrayBuilder, label: String) {
        val data = label.toByteArray(Charsets.US_ASCII)
        builder.addByte(data.size)
        builder.addBytes(data)
    }

    private fun Boolean.asInt(): Int = if (this) 1 else 0
}
