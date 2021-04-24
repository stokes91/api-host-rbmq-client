/*
   Copyright 2020 Alexander Stokes

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

const crypto = require("crypto");
const https = require("https");
const zlib = require("zlib");

const TokenRegex = /^[WXYZBCDEFGHJKLMN][WXYZBCDEFGHJKLMNO123456789PQRTUV]{7}$/;
const TimestampRegex = /^[\d]{4}\-[\d]{2}\-[\d]{2}T[\d]{2}\:[\d]{2}$/;
const DigestRegex = /^[a-f\d]{64}$/;

class Client {
  constructor(options) {
    Object.assign(this, options);
  }

  pingOptions(callback) {
    const req = https.request(
      {
        method: "OPTIONS",
        host: this.host,
        agent: this.agent,
        path: "/",
        headers: {
          cookie: "_x=" + this.token,
          accept: "application/json",
        },
      },
      (res) => {
        callback();
      }
    );

    req.end(Buffer.from(""));
  }

  apiCall(channel, data, callback) {
    const result = {};
    const path = channel + "?" + crypto.randomBytes(16).toString("hex");

    this.postResource(path, data, (err) => {
      if (err) {
        callback(err);
        return;
      }

      const resource = this.getResource(path, (err) => {
        if (err) {
          callback(err);
          return;
        }

        Object.assign(result, resource);

        callback();
      });
    });

    return result;
  }

  getResource(path, callback) {
    const response = {};

    let calledBack = false;
    const callbackOnce = function () {
      if (calledBack) return;
      calledBack = true;
      callback.apply(this, arguments);
    };

    console.log({
      method: "GET",
      host: this.host,
      agent: this.agent,
      path,
      headers: {
        cookie: "_x=" + this.token,
        accept: "application/json",
        "accept-encoding": "br",
      },
    });

    const req = https.request(
      {
        method: "GET",
        host: this.host,
        agent: this.agent,
        path,
        headers: {
          cookie: "_x=" + this.token,
          accept: "application/json",
          "accept-encoding": "br",
        },
      },
      (res) => {
        if (
          res.statusCode !== 200 ||
          res.headers["content-type"] !== "application/json" ||
          !res.headers["content-length"]
        ) {
          callback(true);
          return;
        }

        const b = [];

        const continues = () => {
          const ser = Buffer.concat(b).toString("utf8");

          try {
            Object.assign(response, JSON.parse(ser));
          } catch (e) {
            if (this.verbose) {
              console.log(e, ser);
            }
            callbackOnce(e);
            return;
          }

          callbackOnce(null, response);
          return;
        };

        let decompressionAlg;

        if (res.headers["content-encoding"] === "br") {
          decompressionAlg = zlib.createBrotliDecompress();
        } else {
          res
            .on("data", (d) => {
              b.push(d);
            })
            .on("end", () => {
              continues();
            })
            .on("error", (e) => {
              callbackOnce(e);
            });
          return;
        }

        res.pipe(decompressionAlg);

        decompressionAlg
          .on("data", (d) => {
            b.push(d);
          })
          .on("end", () => {
            continues();
          })
          .on("error", (e) => {
            callbackOnce(e);
          });
      }
    );

    req.end(Buffer.from(""));

    return response;
  }

  postResource(path, object, callback) {
    console.log({
      method: "POST",
      host: this.host,
      agent: this.agent,
      path,
      headers: {
        cookie: "_x=" + this.token,
        "content-type": "application/json",
      },
    });

    const req = https.request(
      {
        method: "POST",
        host: this.host,
        agent: this.agent,
        path,
        headers: {
          cookie: "_x=" + this.token,
          "content-type": "application/json",
        },
      },
      (res) => {
        console.log({ statusCode: res.statusCode, headers: res.headers });
        if (res.statusCode !== 202) {
          callback(null); // Accepted (given when the resource times out after 5 minutes)
          return;
        } else if (
          res.statusCode !== 302 ||
          res.headers.location !== path ||
          res.headers["content-type"] ||
          res.headers["content-length"]
        ) {
          callback(true);
          return;
        }

        callback();
      }
    );

    req.end(Buffer.from(JSON.stringify(object), "utf8"));
  }
}

Client.createClient = (options, callback) => {
  if (!options.host) {
    return;
  } else if (options.authorization) {
    const { authorization, host, verbose } = options.authorization;

    const that = new Client({
      authorization,
      host,
      verbose,
    });

    process.nextTick(callback);

    return that;
  } else if (!options.redisClient) {
    return;
  }

  const { host, redisClient, verbose } = options;

  const that = new Client({ host, verbose });

  redisClient.get("AUTH_TOK", (err, givenToken) => {
    if (err) {
      callback(err);
      return;
    } else if (
      givenToken.length !== 99 ||
      givenToken[8] !== "-" ||
      givenToken[25] !== ":" ||
      givenToken[34] !== "-" ||
      !TokenRegex.test(givenToken.substring(0, 8)) ||
      !TimestampRegex.test(givenToken.substring(9, 25)) ||
      !TokenRegex.test(givenToken.substring(26, 34)) ||
      !DigestRegex.test(givenToken.substring(35, 99))
    ) {
      callback("invalidToken");
      return;
    }

    that.token = givenToken;

    callback();
  });

  return that;
};

module.exports = Client;
