import prologue


# Define response function for prologue
proc hello*(ctx: Context) {.async.} =
  resp "<h1>Hello World!</h1>"

proc register*(ctx: Context) {.async.} =
  resp "<h1>Hello World!</h1>"

# Create new prologue app variable
let app = newApp()

# Define HTTP route and associated function to run when requested
app.get("/", hello)

# Start app
app.run()