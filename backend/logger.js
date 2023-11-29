// ! logging and monitoring

const pino = require("pino");
const Loggly = require("loggly");

const logger = pino({
  level: "info",
});

const logglyConfig = {
  token: process.env.LOGGLY_TOKEN,
  subdomain: process.env.LOGGLY_SUBDOMAIN,
  tags: ["Pino-NodeJS"],
};

const logglyClient = Loggly.createClient(logglyConfig);

logger.info = (...args) => {
  logglyClient.log({ level: "info", msg: args.join(" ") });
  console.info(...args);
};

logger.error = (...args) => {
  logglyClient.log({ level: "error", msg: args.join(" ") });
  console.error(...args);
};

module.exports = logger;
