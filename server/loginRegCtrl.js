const bcrypt = require("bcryptjs")

// req is an object containing information about the HTTP request that raised the event. In response to req, you use res to send back the desired HTTP response.

module.exports = {
  login: async (req, res) => {
    const db = req.app.get("db")
    const { session } = req
    const { loginEmail: email } = req.body

    try {
      let user = await db.login({ email })

      const authenticated = bcrypt.compareSync(req.body.loginPassword, user[0].password)

      if (authenticated) {
        res.status(200).send({
          authenticated,
          user_id: user[0].login_id,
          firstname: user[0].firstname,
          lastname: user[0].lastname,
          email: user[0].email
        })
        session.user = {
          email: user[0].email,
          user_id: user[0].login_id,
          authenticated: true,
          firstname: user[0].firstname,
          lastname: user[0].lastname
        }
      } else {
        throw new Error(401)
      }
    } catch (err) {
      res.sendStatus(401)
    }
  },

  register: async (req, res) => {
    const db = req.app.get("db")
    const { firstname, lastname, email, password } = req.body
    const { session } = req

    let emailTaken = await db.checkEmail({ email })
    emailTaken = +emailTaken[0].count
    if (emailTaken !== 0) {
      return res.sendStatus(409)
    }

    const salt = bcrypt.genSaltSync(10)
    const hash = bcrypt.hashSync(password, salt)

    const user = await db.registerUser({
      firstname,
      lastname,
      email,
      hash
    })

    session.user = {
      authenticated: true,
      email: user[0].email,
      user_id: user[0].login_id,
      firstname: user[0].firstname,
      lastname: user[0].lastname
    }

    res.status(200).send({
      authenticated: true,
      email: user[0].email,
      user_id: user[0].login_id,
      firstname: user[0].firstname,
      lastname: user[0].lastname
    })
  }
}