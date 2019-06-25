'use strict'


const express = require("express")
const cors = require("cors")
const atob = require("atob")
const got = require("got")
const URL = require("url")
const path = require("path")

const addToUrl = (url, trailing) => {
  const { pathname } = URL.parse(url)
  return URL.resolve(url, path.join(pathname, trailing))
}

const hasWellKnown = url => url.indexOf(".well-known") !== -1

const getJWKS = url => {
  // Some jwks endpoints are served with certs signed
  // by industry specific CAs. As this is a debugging
  // utility, such endpoints should be supported
  return got(url, { json: true, rejectUnauthorized: false })
    .then(({ body }) => {
      if (body.keys) {
        return body
      }
      if (body.jwks_uri) {
        return getJWKS(body.jwks_uri)
      }
      if (!hasWellKnown(url)) {
        return getJWKS(addToUrl(url, "/.well-known/openid-configuration"))
      }
      throw new Error("No Keys found")
    })
    .catch(err => {
      if (!hasWellKnown(url)) {
        return getJWKS(addToUrl(url, "/.well-known/openid-configuration"))
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

module.exporta = app