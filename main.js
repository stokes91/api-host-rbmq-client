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
const util = require("util");
const https = require("https");

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
          authorization: this.authorization,
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
    const resource = {};

    const req = https.request(
      {
        method: "GET",
        host: this.host,
        agent: this.agent,
        path,
        headers: {
          authorization: this.authorization,
          accept: "application/json",
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
        res.on("data", (d) => {
          b.push(d);
        });
        res.on("end", () => {
          try {
            Object.assign(
              resource,
              JSON.parse(Buffer.concat(b).toString("utf8"))
            );
          } catch (err) {
            callback(err);
            return;
          }

          callback();
        });
      }
    );

    req.end(Buffer.from(""));

    return resource;
  }

  postResource(path, object, callback) {
    const req = https.request(
      {
        method: "POST",
        host: this.host,
        agent: this.agent,
        path,
        headers: {
          authorization: this.authorization,
          "content-type": "application/json",
        },
      },
      (res) => {
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
    } else if (givenToken.substring(9, 25) < new Date().toISOString()) {
      callback("expiredToken");
      return;
    }

    that.authorization = "Basic " + Buffer.from(givenToken).toString("base64");

    callback();
  });

  return that;
};

module.exports = Client;
