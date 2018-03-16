// Some jwks endpoints are served with certs signed
// by industry specific CAs. As this is a debugging
// utility, such endpoints should be supported
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

const express = require("express")
const cors = require("cors")
const atob = require("atob")
const got = require("got")
const { resolve } = require("url")

const getJWKS = url => {
  return got(url, { json: true })
    .then(({ body }) => {
      if (body.keys) {
        return body
      }
      if (body.jwks_uri) {
        return getJWKS(body.jwks_uri)
      }
      if (url.indexOf("./well-known") !== -1) {
        return getJWKS(resolve(url, "/.well-known/openid-configuration"))
      }
      throw new Error("No Keys found")
    })
    .catch(err => {
      if (err.statusCode === 200 && url.indexOf("./well-known") === -1) {
        return getJWKS(resolve(url, "/.well-known/openid-configuration"))
      }
      throw err
    })
}

const app = express()
app.use(cors())

app.get("/:issuer", (req, res) => {
  const issuer = atob(req.params.issuer)
  if (issuer.indexOf("http") !== 0) {
    return res.status(404).send()
  }
  getJWKS(issuer)
    .then(data => {
      res.json(data)
    })
    .catch(err => {
      console.log(err)
      res.status(404).send()
    })
})

app.listen(3001)
