require("dotenv").config()
const express = require("express")
const app = express()
const massive = require("massive")
const session = require("express-session")
const { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env

// -- MIDDLEWARE -- //
app.use(express.json())

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 1
  }
}))

app.use(express.static(`${__dirname}/../build`));

// -- MASSIVE -- //
massive(CONNECTION_STRING).then((database) => {
  app.set("db", database)
  console.log("database set!")
  console.log(database.listTables())
  app.listen(SERVER_PORT, () => {
    console.log(`listening on port ${SERVER_PORT}`)
  })
})

// -- END POINTS -- //

// Authentication
app.post("auth/login")
app.post("auth/registration")




