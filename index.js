"use strict"
const {parse, resolve} = require("url")
const {send} = require("micro")
const cors = require("micro-cors")()
const atob = require("atob")
const got = require("got")
const path = require("path")

const addToUrl = (url, trailing) => {
  const {pathname} = parse(url)
  return resolve(url, path.join(pathname, trailing))
}

const hasWellKnown = url => url.indexOf(".well-known") !== -1

const getJWKS = url => {
  // Some jwks endpoints are served with certs signed
  // by industry specific CAs. As this is a debugging
  // utility, such endpoints should be supported
  return got(url, {json: true, rejectUnauthorized: false})
    .then(({body}) => {
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

const handler = (req, res) => {
  const {path} = parse(req.url, true)
  const issuer = atob(path.replace("/", ""))
  if (issuer.indexOf("http") !== 0) {
    return send(res, 404)
  }
  getJWKS(issuer)
    .then(data => {
      send(res, 200, data)
    })
    .catch(err => {
      console.log(err)
      send(res, 500, err)
    })
}

module.exports = cors(handler)
