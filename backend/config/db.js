const mysql = require("mysql2");
require("dotenv").config();

const pool = mysql.createPool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  port: process.env.DATABASE_PORT,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

pool.getConnection((err) => {
  if (err) {
    console.log(err.message);
  } else {
    console.log("DB Connection established!");
  }
});

module.exports = pool.promise();
