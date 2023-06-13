package com.dpforge.dns.client.message

class Question(
    val name: String,
    val type: ResourceRecord.Type,
    val clazz: ResourceRecord.Class
)