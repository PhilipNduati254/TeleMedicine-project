const mysql = require('mysql2');
require('dotenv').config();

const initialConnect = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
});

initialConnect.connect((err) => {
  if (err) {
    console.log('Error connecting to database:', err.stack);
    return;
  }
  console.log('Connected to database');
});

module.exports = initialConnect;

