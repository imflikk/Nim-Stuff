import prologue
import json


# Define response function for prologue
proc hello*(ctx: Context) {.async.} =
  resp "<h1>Hello World!</h1>"

proc register*(ctx: Context) {.async.} =
  let bodyStr = ctx.request.body
  let jsonData = parseJson(bodyStr)
  let data = jsonData["data"].getStr()

  resp "Received: " & data

# Create new prologue app variable
let app = newApp()

# Define HTTP route and associated function to run when requested
app.addRoute("/", hello, HttpGet)
app.addRoute("/register", register, HttpPost)

# Start app
app.run()