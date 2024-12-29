const express = require('express');
const path = require('path');

const bcrypt = require('bcryptjs');
const session = require('express-session');
const mysql = require('mysql2');
require('dotenv').config();
const moment = require('moment');
console.log(moment().format('YYYY-MM-DD HH:mm:ss'));
const { isAuthenticated, isAdmin, isDoctor } = require('./middleware/authMiddleware');
// const password = '34102738';
const http = require('http');  // Import the http module
const socketIo = require('socket.io');  // Import socket.io for real-time communication



const app = express();
const server = http.createServer(app);  // This creates the HTTP server

// Step 3: Initialize socket.io with the HTTP server
const io = socketIo(server);  // This binds socket.io to the HTTP server


// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Optional if views are in a custom directory
// Serve static files (images, CSS, JS) from the 'asset' directory
app.use('/asset', express.static(path.join(__dirname, 'asset')));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,  // Cookie can't be accessed via JavaScript
    secure: false    // Set to true if you're using HTTPS
  }
}));
// Database connection setup
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to telemedicine_db');
});

// Define the port
const port = 3301;

// Handle Socket.io connections
io.on('connection', (socket) => {
  console.log('A user connected');
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});


// Routes for inserting admin
// bcrypt.hash(password, 10, (err, hashedPassword) => {
//   if (err) throw err;

//   const sql = 'INSERT INTO Admin (email, password_hash, role) VALUES (?, ?, ?)';
//   db.query(sql, ['admin@example.com', hashedPassword, 'admin'], (err, result) => {
//     if (err) throw err;
//     console.log('Super admin created successfully!');
//   });
// });

// Route to get a list of doctors (for the dropdown)
// Route to show chat page and fetch doctors for the dropdown
// Route to get a list of doctors (for the dropdown)
// Route to render the chat page

// Store clients (for tracking connected users)
let clients = {};

// Socket.io connection
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Handle join event where users are assigned an ID (either doctor or patient)
  socket.on('join', (userId) => {
    clients[userId] = socket.id;  // Track the user by their userId
    console.log(`${userId} joined the chat`);
  });

  // Handle sendMessage event
  socket.on('sendMessage', (data) => {
    const { sender, receiver, message, patientId, doctorId } = data;

    // Insert the message into the database
    db.query(`
      INSERT INTO chat_messages (patient_id, doctor_id, message, sender, is_read)
      VALUES (?, ?, ?, ?, 0)`,
      [patientId, doctorId, message, sender], (err) => {
        if (err) {
          console.error('Error saving message:', err);
        } else {
          // Emit the message to the receiver (doctor or patient)
          if (clients[receiver]) {
            io.to(clients[receiver]).emit('receiveMessage', {
              sender,
              message,
            });
          }
        }
      });
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('A user disconnected:', socket.id);
    // Remove the user from the clients object when they disconnect
    for (let userId in clients) {
      if (clients[userId] === socket.id) {
        delete clients[userId];
        break;
      }
    }
  });
});




// Route to fetch doctors and render the chat page
// Route to show all doctors
app.get('/patient/select-doctor', (req, res) => {
  // Ensure patient is logged in
  const patientId = req.session.patientId;
  if (!patientId) {
    return res.redirect('/login');
  }

  // Fetch all doctors from the database
  db.query('SELECT id, first_name, last_name, specialization FROM Doctors', (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error fetching doctors');
    }

    // Render the select-doctor page with the list of doctors
    res.render('select-doctor', { doctors: results });
  });
});

// Route to display chat page with doctor
// Route to mark messages as read for the patient and doctor when the chat is opened
app.get('/patient/chat', (req, res) => {
  const patientId = req.session.patientId; // Ensure patient is logged in
  const doctorId = req.query.doctorId; // Doctor ID passed as a query parameter

  if (!patientId || !doctorId) {
    return res.redirect('/login'); // Redirect to login page if patient is not logged in or doctorId is missing
  }

  console.log(`Doctor ID: ${doctorId}`); // Log the doctorId to ensure it's passed correctly

  // Fetch doctor details from the database using the doctorId
  db.query('SELECT * FROM Doctors WHERE id = ?', [doctorId], (err, doctorResult) => {
    if (err || doctorResult.length === 0) {
      console.error(err);  // Log error if query fails or no doctor is found
      return res.status(500).send('Error fetching doctor details');
    }

    const doctor = doctorResult[0]; // Assuming the query returns a single doctor
    console.log(doctor);  // Log the doctor to confirm it's being fetched correctly

    // Fetch the chat history for the patient and the selected doctor
    const sql = `
      SELECT * FROM chat_messages
      WHERE (patient_id = ? AND doctor_id = ?) OR (doctor_id = ? AND patient_id = ?)
      ORDER BY timestamp ASC
    `;

    db.query(sql, [patientId, doctorId, doctorId, patientId], (err, messageResults) => {
      if (err) {
        console.error('Error fetching chat history:', err);
        return res.status(500).send('Database error');
      }

      // Mark messages as read when the chat page is opened (for both doctor and patient)
      const updateSql = `
        UPDATE chat_messages 
        SET is_read = 1 
        WHERE (patient_id = ? AND doctor_id = ? AND is_read = 0) 
           OR (doctor_id = ? AND patient_id = ? AND is_read = 0)
      `;

      db.query(updateSql, [patientId, doctorId, doctorId, patientId], (err, updateResult) => {
        if (err) {
          console.error('Error updating read status:', err);
          return res.status(500).send('Database error');
        }

        console.log(`Marked ${updateResult.affectedRows} messages as read.`);

        // Render the chat page with the doctor, patient ID, and message history
        res.render('patient-chat', {
          doctor: doctor,             // Include doctor info (if needed)
          patientId: patientId,
          doctorId: doctorId,
          messages: messageResults   // Pass the messages to the EJS template
        });
      });
    });
  });
});

// Route to fetch chat history for a patient
app.get('/patient/chat/history', (req, res) => {
  const patientId = req.session.patientId;
  const doctorId = req.query.doctorId;  // Doctor ID passed as a query parameter
  
  if (!patientId || !doctorId) {
    return res.status(400).send('Patient ID or Doctor ID is missing.');
  }

  // SQL query to fetch the chat messages for the patient and the selected doctor
  const sql = `
    SELECT * FROM chat_messages
    WHERE (patient_id = ? AND doctor_id = ?) OR (doctor_id = ? AND patient_id = ?)
    ORDER BY timestamp ASC
  `;

  db.query(sql, [patientId, doctorId, doctorId, patientId], (err, results) => {
    if (err) {
      console.error('Error fetching chat history:', err);
      return res.status(500).send('Database error');
    }

    // Render the chat page with the doctor, patient ID, and message history
    res.render('patient-chat', {
      doctor: results[0].doctor,  // Include doctor info (if needed)
      patientId: patientId,
      doctorId: doctorId,
      messages: results
    });
  });
});

app.get('/patient/chat/:doctorId', (req, res) => {
  const doctorId = req.params.doctorId;
  const patientId = req.user.id;  // Assuming `req.user.id` stores the patient’s ID
  
  if (!doctorId) {
    return res.status(400).send('No doctor selected');
  }

  // Fetch messages for this doctor and patient
  db.query(
    'SELECT * FROM chat_messages WHERE doctor_id = ? AND patient_id = ? ORDER BY timestamp ASC',
    [doctorId, patientId],
    (err, results) => {
      if (err) {
        console.error('Error fetching messages:', err);
        return res.status(500).send('Error fetching messages');
      }

      // Render the patient-chat view, passing the doctor, patient ID, and messages
      res.render('patient-chat', {
        doctorId: doctorId,
        patientId: patientId,
        messages: results,  // Make sure the messages are passed here
      });
    }
  );
});


// Route to send a message from the patient to the doctor
app.post('/patient/chat/send-message', (req, res) => {
  const { doctorId, patientId, text } = req.body;

  // Insert the message into the database
  db.query(
    'INSERT INTO chat_messages (doctor_id, patient_id, message, sender, is_read) VALUES (?, ?, ?, ?, 0)', 
    [doctorId, patientId, text, 'patient'], 
    (err, result) => {
      if (err) {
        console.error('Error saving message:', err);
        return res.status(500).json({ success: false });
      }

      // Emit the message to the doctor via Socket.IO
      if (clients[doctorId]) {
        io.to(clients[doctorId]).emit('receiveMessage', {
          sender: 'patient',
          message: text,
        });
      }

      // Respond with success
      res.json({ success: true });
    }
  );
});

app.post('/patient/chat/mark-read', (req, res) => {
  const { patientId, doctorId, messageId } = req.body;

  if (!patientId || !doctorId || !messageId) {
    return res.status(400).send('Missing parameters');
  }

  // Update the 'is_read' status for the specified message
  const sql = `
    UPDATE chat_messages 
    SET is_read = 1 
    WHERE id = ? AND (patient_id = ? OR doctor_id = ?)
  `;

  db.query(sql, [messageId, patientId, doctorId], (err, result) => {
    if (err) {
      console.error('Error marking message as read:', err);
      return res.status(500).send('Database error');
    }

    console.log(`Marked message ID ${messageId} as read.`);
    res.json({ success: true });
  });
});


// Route to render the doctor's chat page with notifications for unread messages
app.get('/doctor/chat', (req, res) => {
  const doctorId = req.session.doctorId;

  if (!doctorId) {
    return res.redirect('/login');
  }

  // Fetch the doctor's details
  db.query('SELECT first_name, last_name FROM doctors WHERE id = ?', [doctorId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error fetching doctor details');
    }

    if (results.length === 0) {
      return res.status(404).send('Doctor not found');
    }

    const doctor = results[0];

    // Fetch a specific patient's ID (this should be based on your app logic)
    const patientId = req.query.patientId;  // Assuming patientId is passed as a query parameter

    // Fetch the list of patients with unread messages (Optional, if you need notifications)
    db.query(`
      SELECT patients.id AS patientId, patients.first_name, patients.last_name, 
             COUNT(chat_messages.id) AS unreadMessages
      FROM patients
      LEFT JOIN chat_messages ON chat_messages.patient_id = patients.id
      AND chat_messages.doctor_id = ? 
      AND chat_messages.is_read = 0
      GROUP BY patients.id
      HAVING COUNT(chat_messages.id) > 0`,
      [doctorId], (err, notifications) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Error fetching chat notifications');
        }

        // Render the page with doctor, patientId, and notifications data
        res.render('doctor-chat', {
          doctor: doctor,
          patientId: patientId, // Include patientId here
          notifications: notifications
        });
      });
  });
});


app.get('/doctor/chat/history/:patientId', (req, res) => {
  console.log('Received request for chat history:', req.params);
  const doctorId = req.session.doctorId;
  const patientId = req.params.patientId;

  if (!doctorId || !patientId) {
    return res.status(400).send('Doctor ID or Patient ID is missing.');
  }

  // Fetch chat messages
  const sql = `
    SELECT * FROM chat_Messages
    WHERE (doctor_id = ? AND patient_id = ?)
    OR (doctor_id = ? AND patient_id = ?)
    ORDER BY timestamp ASC
  `;
  
  db.query(sql, [doctorId, patientId, patientId, doctorId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }

    res.render('chat-history', {
      doctorId: doctorId,
      patientId: patientId,
      messages: results
    });
  });
});



// Route to send a message from the doctor
app.post('/doctor/chat/send-message', (req, res) => {
  let { doctorId, patientId, text } = req.body;

  // Log received data for debugging
  console.log('Received data:', req.body);

  // Ensure doctorId and patientId are integers (in case they are passed as strings)
  doctorId = parseInt(doctorId, 10);
  patientId = parseInt(patientId, 10);

  if (!doctorId || !patientId || !text) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  // Insert the message into the database
  db.query(
    'INSERT INTO chat_messages (doctor_id, patient_id, message, sender, is_read) VALUES (?, ?, ?, ?, 0)',
    [doctorId, patientId, text, 'doctor'],  // Ensure the correct values are passed
    (err, result) => {
      if (err) {
        console.error('Error saving message:', err);
        return res.status(500).json({ success: false });
      }

      // Emit the message to the patient if connected
      if (clients[patientId]) {
        io.to(clients[patientId]).emit('receiveMessage', {
      
          sender: 'doctor',
          message: text,
          doctorId: doctorId,
          patientId: patientId
        });
      }

      // Respond with success
      res.json({ success: true });
    }
  );
});



// Landing page (home route)
app.get('/', (req, res) => {
  res.render('index'); // Render the landing page (index.ejs)
});

// Patient registration
app.get('/register', (req, res) => {
  res.render('register'); // Render the registration form
});

app.post('/register', (req, res) => {
  const { first_name, last_name, email, password, phone, date_of_birth, gender, address } = req.body;
  const password_hash = bcrypt.hashSync(password, 10);
  
  const sql = 'INSERT INTO Patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  db.query(sql, [first_name, last_name, email, password_hash, phone, date_of_birth, gender, address], (err, result) => {
    if (err) {
      console.error('Error during registration:', err);
      return res.status(500).send('Error during registration');
    }
    res.redirect('/login'); // Redirect to login page after successful registration
  });
});









// log in page


// Define the login page route (GET method)
app.get('/login', (req, res) => {
  res.render('login');  // Render the login page (login.ejs)
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Query the database for a patient with the provided email
  const sqlPatient = 'SELECT * FROM Patients WHERE email = ?';
  db.query(sqlPatient, [email], (err, patientResults) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }

    // If a patient is found, compare the password
    if (patientResults.length > 0) {
      const patient = patientResults[0];
      if (bcrypt.compareSync(password, patient.password_hash)) {
        req.session.patientId = patient.id;  // Store the patient ID in session
        return res.redirect('/dashboard');   // Redirect to the patient dashboard
      } else {
        return res.status(401).send('Invalid credentials');
      }
    }

    // If no patient found, check the Admin table for admin or doctor roles
    const sqlAdmin = 'SELECT * FROM Admin WHERE email = ?';
    db.query(sqlAdmin, [email], (err, adminResults) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Database error');
      }

      if (adminResults.length > 0) {
        const admin = adminResults[0];

        // Compare the password hash
        if (bcrypt.compareSync(password, admin.password_hash)) {
          req.session.adminId = admin.id;  // Store admin ID in session
          req.session.role = admin.role;    // Store role (admin/doctor)

          // If the user is an admin
          if (admin.role === 'admin') {
            return res.redirect('/admin/dashboard');
          }

          // If the user is a doctor
          if (admin.role === 'doctor') {
            // Log admin ID for debugging
            console.log('Admin ID:', admin.id);
            console.log('Doctor Role: Doctor');

            // Now, check if the email exists in the Doctors table
            const sqlDoctor = 'SELECT * FROM Doctors WHERE email = ?';
            db.query(sqlDoctor, [email], (err, doctorResults) => {
              if (err) {
                console.error(err);
                return res.status(500).send('Database error');
              }

              // If the doctor exists in the Doctors table
              if (doctorResults.length > 0) {
                const doctor = doctorResults[0];
                console.log('Doctor found:', doctor.first_name, doctor.last_name);

                // Store the doctor ID in session and redirect to the doctor dashboard
                req.session.doctorId = doctor.id;  // Store the doctor ID in session
                return res.redirect('/doctor/dashboard');
              } else {
                console.log('Doctor not found in Doctors table');
                return res.status(404).send('Doctor not found');
              }
            });
          }
        } else {
          return res.status(401).send('Invalid credentials');
        }
      } else {
        return res.status(401).send('Invalid credentials');
      }
    });
  });
});



// log out

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');  // Redirect to the login page after logout
  });
});




// patients dashboard
app.get('/dashboard', (req, res) => {
  // Check if the patient is logged in (session has patientId)
  if (!req.session.patientId) {
    return res.redirect('/login');  // Redirect to login page if not logged in
  }

  const patientId = req.session.patientId;

  // Query to get the total number of doctors
  db.query('SELECT COUNT(*) AS doctorCount FROM Doctors', (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send('Error fetching doctor count');
    }

    const doctorCount = results[0]?.doctorCount || 0;  // Default to 0 if undefined

    // Query to get patient details based on the patientId
    db.query('SELECT * FROM Patients WHERE id = ?', [patientId], (err, patientResults) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send('Error fetching patient data');
      }

      const patientData = patientResults[0] || {};  // Default to empty object if no data

      // Render the dashboard page and pass the doctorCount and patientData
      res.render('dashboard', { doctorCount, patientData });
    });
  });
});



// Delete Patient Profile
app.post('/delete-profile', (req, res) => {
  const patientId = req.session.patientId;
  const sql = 'DELETE FROM Patients WHERE id = ?';
  db.query(sql, [patientId], (err, result) => {
    if (err) {
      console.error('Error deleting profile:', err);
      return res.status(500).send('Error deleting profile');
    }
    req.session.destroy();
    res.redirect('/');
  });
});



// Route to create an appointment and generate Jitsi meeting link
// Function to create Jitsi meeting link

// Function to create Jitsi meeting link
function createJitsiMeeting(appointmentDetails) {
  return new Promise((resolve, reject) => {
    const jitsiBaseUrl = 'https://meet.jit.si';  // Public Jitsi server

    // Ensure we have the doctor and patient names properly set
    const doctorFirstName = appointmentDetails.doctor_first_name;
    const doctorLastName = appointmentDetails.doctor_last_name;
    const patientFirstName = appointmentDetails.patient_first_name;
    const patientLastName = appointmentDetails.patient_last_name;

    if (!doctorFirstName || !doctorLastName || !patientFirstName || !patientLastName) {
      reject('Missing doctor or patient details');
      return;
    }

    // Generate a unique room name using template literals
    const roomName = `appointment-${doctorFirstName}-${doctorLastName}-${patientFirstName}-${patientLastName}-${Date.now()}`;

    // Generate the full Jitsi URL
    const jitsiUrl = `${jitsiBaseUrl}/${roomName}`;

    console.log('Generated Jitsi URL:', jitsiUrl);  // Debugging the generated URL

    // Resolve with the generated link
    resolve(jitsiUrl);
  });
}

// Route to create an appointment and generate Jitsi meeting link
app.post('/appointment', (req, res) => {
  const { doctor_id, patient_id, appointment_date, appointment_time } = req.body;

  const sqlDoctor = 'SELECT first_name, last_name FROM Doctors WHERE id = ?';
  const sqlPatient = 'SELECT first_name, last_name FROM Patients WHERE id = ?';

  db.query(sqlDoctor, [doctor_id], (err, doctorRows) => {
    if (err) {
      console.error('Error fetching doctor details:', err);
      return res.status(500).send('Error fetching doctor details');
    }

    if (!doctorRows || doctorRows.length === 0) {
      return res.status(400).send('Doctor not found');
    }
    const doctor = doctorRows[0];
    console.log('Doctor details:', doctor);

    db.query(sqlPatient, [patient_id], (err, patientRows) => {
      if (err) {
        console.error('Error fetching patient details:', err);
        return res.status(500).send('Error fetching patient details');
      }

      if (!patientRows || patientRows.length === 0) {
        return res.status(400).send('Patient not found');
      }
      const patient = patientRows[0];
      console.log('Patient details:', patient);

      const appointmentDetails = {
        doctor_first_name: doctor.first_name,
        doctor_last_name: doctor.last_name,
        patient_first_name: patient.first_name,
        patient_last_name: patient.last_name,
        appointment_date,
        appointment_time
      };

      // Check if doctor and patient details are available before creating the Jitsi meeting
      if (!appointmentDetails.doctor_first_name || !appointmentDetails.patient_first_name) {
        return res.status(400).send('Missing doctor or patient details');
      }

      createJitsiMeeting(appointmentDetails)
        .then(meetLink => {
          if (meetLink) {
            const sqlInsert = `
              INSERT INTO Appointments (patient_id, doctor_id, appointment_date, appointment_time, status, jitsi_link)
              VALUES (?, ?, ?, ?, ?, ?)
            `;
            db.query(sqlInsert, [patient_id, doctor_id, appointment_date, appointment_time, 'Scheduled', meetLink], (err, result) => {
              if (err) {
                console.error('Error saving appointment:', err);
                return res.status(500).send('Error saving appointment');
              }
              console.log('Appointment saved with Jitsi link:', meetLink);
              res.redirect('/appointments'); 
            });
          } else {
            res.status(500).send('Error creating Jitsi link');
          }
        })
        .catch(error => {
          console.error('Error creating Jitsi event:', error);
          res.status(500).send('Error creating Jitsi event');
        });
    });
  });
});

// Route to get appointments and render them with Jitsi links
// Route to get appointments and render them with Jitsi links
app.get('/appointment', (req, res) => {
  const sql = `
    SELECT a.*, d.first_name AS doctor_first_name, d.last_name AS doctor_last_name
    FROM Appointments a
    JOIN Doctors d ON a.doctor_id = d.id
    WHERE a.patient_id = ?
  `;
  db.query(sql, [req.session.patientId], (err, results) => {
    if (err) {
      console.error('Error fetching appointments:', err);
      return res.status(500).send('Error fetching appointments');
    }

    // Map over appointments and ensure Jitsi link is available
    results.forEach(appointment => {
      // Add the doctor’s full name
      appointment.doctor_name = `${appointment.doctor_first_name} ${appointment.doctor_last_name}`;
    });

    // Render the patient appointments page
    res.render('appointments', { appointments: results });
  });
});


// Book Appointment Route
app.get('/book-appointment', (req, res) => {
  const patientId = req.session.patientId;
  if (!patientId) {
    return res.redirect('/login');  // Ensure patient is logged in
  }

  // Get the list of doctors to show in the selection
  const sql = 'SELECT * FROM Doctors';
  db.query(sql, (err, doctors) => {
    if (err) {
      console.error('Error fetching doctors:', err);
      return res.status(500).send('Error fetching doctors');
    }

    res.render('book-appointment', { 
      doctors, 
      error: null,
      activeRoute: '/book-appointment' // Active route for sidebar
    });
  });
});



app.post('/book-appointment', (req, res) => {
  const { doctor_id, appointment_date, appointment_time } = req.body;
  const patientId = req.session.patientId;

  // Check if the doctor is available at the requested time
  const checkAvailabilityQuery = `
    SELECT * FROM Appointments 
    WHERE doctor_id = ? 
    AND appointment_date = ? 
    AND appointment_time = ?
  `;
  
  db.query(checkAvailabilityQuery, [doctor_id, appointment_date, appointment_time], (err, existingAppointments) => {
    if (err) {
      console.error('Error checking availability:', err);
      return res.status(500).send('Error checking availability');
    }

    if (existingAppointments.length > 0) {
      // If slot is taken, show error and pass doctors data to the view again
      const sql = 'SELECT * FROM Doctors';  // Query to fetch doctors from the database
      db.query(sql, (err, doctors) => {
        if (err) {
          console.error('Error fetching doctors:', err);
          return res.status(500).send('Error fetching doctors');
        }

        return res.render('book-appointment', {
          error: 'This slot is already taken. Please choose another time.',
          doctors,           // Pass doctors data to the template
          activeRoute: '/book-appointment'
        });
      });
    } else {
      // Fetch doctor details
      const sqlDoctor = 'SELECT first_name, last_name FROM Doctors WHERE id = ?';
      db.query(sqlDoctor, [doctor_id], (err, doctorRows) => {
        if (err) {
          console.error('Error fetching doctor details:', err);
          return res.status(500).send('Error fetching doctor details');
        }

        if (!doctorRows || doctorRows.length === 0) {
          return res.status(400).send('Doctor not found');
        }
        const doctor = doctorRows[0];
        console.log('Doctor details:', doctor);  // Log doctor details

        // Fetch patient details
        const sqlPatient = 'SELECT first_name, last_name FROM Patients WHERE id = ?';
        db.query(sqlPatient, [patientId], (err, patientRows) => {
          if (err) {
            console.error('Error fetching patient details:', err);
            return res.status(500).send('Error fetching patient details');
          }

          if (!patientRows || patientRows.length === 0) {
            return res.status(400).send('Patient not found');
          }
          const patient = patientRows[0];
          console.log('Patient details:', patient);  // Log patient details

          // Insert the appointment into the database
          const sqlInsert = `
            INSERT INTO Appointments (patient_id, doctor_id, appointment_date, appointment_time, status) 
            VALUES (?, ?, ?, ?, ?)
          `;
          db.query(sqlInsert, [patientId, doctor_id, appointment_date, appointment_time, 'Scheduled'], (err, result) => {
            if (err) {
              console.error('Error booking appointment:', err);
              return res.status(500).send('Error booking appointment');
            }

            // Now create the Jitsi link after the appointment is booked
            const appointmentDetails = {
              doctor_first_name: doctor.first_name,
              doctor_last_name: doctor.last_name,
              patient_first_name: patient.first_name,
              patient_last_name: patient.last_name,
              appointment_date,
              appointment_time
            };

            console.log('Appointment Details:', appointmentDetails);  // Log appointment details

            createJitsiMeeting(appointmentDetails)
              .then(meetLink => {
                if (meetLink) {
                  const updateSql = 'UPDATE Appointments SET jitsi_link = ? WHERE id = ?';
                  db.query(updateSql, [meetLink, result.insertId], (err, updateResult) => {
                    if (err) {
                      console.error('Error updating appointment with Jitsi link:', err);
                      return res.status(500).send('Error updating appointment with Jitsi link');
                    }

                    console.log('Appointment saved with Jitsi link:', meetLink);
                    res.redirect('/appointments'); // Redirect to appointments page
                  });
                } else {
                  console.error('Error creating Jitsi link');
                  res.status(500).send('Error creating Jitsi link');
                }
              })
              .catch(error => {
                console.error('Error creating Jitsi event:', error);
                res.status(500).send('Error creating Jitsi event');
              });
          });
        });
      });
    }
  });
});



// Delete Patient Profile
app.post('/delete-profile', (req, res) => {
  const patientId = req.session.patientId;
  const sql = 'DELETE FROM Patients WHERE id = ?';
  db.query(sql, [patientId], (err, result) => {
    if (err) {
      console.error('Error deleting profile:', err);
      return res.status(500).send('Error deleting profile');
    }
    req.session.destroy();
    res.redirect('/');
  });
});

// Update Patient Profile
app.get('/updateprofile', (req, res) => {
  const patientId = req.session.patientId;

  // Assuming you're querying the database to get the current patient's profile
  const sql = 'SELECT * FROM Patients WHERE id = ?';
  db.query(sql, [patientId], (err, result) => {
    if (err) {
      console.error('Error fetching patient profile:', err);
      return res.status(500).send('Error fetching profile');
    }

    // If the patient is found, render the update profile page with the patient's data
    if (result.length > 0) {
      const patient = result[0]; // Get the patient data
      res.render('updateprofile', { patient });
    } else {
      res.status(404).send('Patient not found');
    }
  });
})



app.post('/updateprofile', (req, res) => {
  const { first_name, last_name, email, phone, date_of_birth, gender, address } = req.body;
  const patientId = req.session.patientId;

  const sql = 'UPDATE Patients SET first_name = ?, last_name = ?, email = ?, phone = ?, date_of_birth = ?, gender = ?, address = ? WHERE id = ?';
  db.query(sql, [first_name, last_name, email, phone, date_of_birth, gender, address, patientId], (err, result) => {
    if (err) {
      console.error('Error updating patient profile:', err);
      return res.status(500).send('Error updating profile');
    }
    res.redirect('/dashboard');
  });
});

app.post('/cancel-appointment/:id', (req, res) => {
  const appointmentId = req.params.id;
  const patientId = req.session.patientId;
  
  const sql = 'UPDATE Appointments SET status = "Canceled" WHERE id = ? AND patient_id = ?';
  db.query(sql, [appointmentId, patientId], (err, result) => {
    if (err) {
      console.error('Error canceling appointment:', err);
      return res.status(500).send('Error canceling appointment');
    }
    res.redirect('/appointments');
  });
});






// Appointment Booking (for Patients)
app.get('/appointments', (req, res) => {
  const patientId = req.session.patientId;
  if (!patientId) return res.redirect('/login');
  
  const sql = 'SELECT * FROM Appointments WHERE patient_id = ?';
  db.query(sql, [patientId], (err, results) => {
    if (err) {
      console.error('Error fetching appointments:', err);
      return res.status(500).send('Error fetching appointments');
    }
    res.render('appointments', { appointments: results });
  });
});

app.get('/book-appointment', (req, res) => {
  const patientId = req.session.patientId;
  if (!patientId) {
    return res.redirect('/login'); // Ensure patient is logged in
  }

  // Get the list of doctors to show in the selection
  const sql = 'SELECT * FROM Doctors';
  db.query(sql, (err, doctors) => {
    if (err) {
      console.error('Error fetching doctors:', err);
      return res.status(500).send('Error fetching doctors');
    }

    res.render('book-appointment', { doctors });
  });
});

app.post('/book-appointment', (req, res) => {
  const { doctor_id, appointment_date, appointment_time } = req.body;
  const patientId = req.session.patientId;

  if (!patientId) {
    return res.redirect('/login'); // Ensure patient is logged in
  }

  // Check if the doctor is available at the selected time
  const checkAvailabilityQuery = `
    SELECT * FROM Appointments 
    WHERE doctor_id = ? 
    AND appointment_date = ? 
    AND appointment_time = ?
  `;
  
  db.query(checkAvailabilityQuery, [doctor_id, appointment_date, appointment_time], (err, existingAppointments) => {
    if (err) {
      console.error('Error checking availability:', err);
      return res.status(500).send('Error checking availability');
    }

    if (existingAppointments.length > 0) {
      return res.render('book-appointment', { 
        error: 'This slot is already taken. Please choose another time.',
        doctors: [] // pass doctors data if needed for re-selection
      });
    }

    // Insert the new appointment if no conflict
    const sql = 'INSERT INTO Appointments (patient_id, doctor_id, appointment_date, appointment_time, status) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [patientId, doctor_id, appointment_date, appointment_time, 'Scheduled'], (err, result) => {
      if (err) {
        console.error('Error booking appointment:', err);
        return res.status(500).send('Error booking appointment');
      }
      res.redirect('/appointments');  // Redirect to the appointments page after booking
    });
  });
});







// admin login
// Admin login page GET handler
// Admin login GET route
// app.get('/admin/login', (req, res) => {
//   res.render('admin_login');  // Render the login page for admin
// });

// app.post('/admin/login', (req, res) => {
//   const { email, password } = req.body;

//   // Query to select user with provided email and role 'admin' or 'doctor'
//   const sql = 'SELECT * FROM Admin WHERE email = ?';
//   db.query(sql, [email], (err, results) => {
//     if (err) {
//       console.error(err);
//       return res.status(500).send('Database error');
//     }

//     // Check if the results contain a user
//     if (results.length > 0) {
//       const user = results[0];

//       // Compare the password with the hashed password stored in the database
//       if (bcrypt.compareSync(password, user.password_hash)) {
//         req.session.adminId = user.id;  // Store admin ID for admin role
//         req.session.role = user.role;    // Store user role in session

//         // Log session data for debugging
//         console.log('Session after login:', req.session);

//         // Check if the user is an admin or doctor and redirect accordingly
//         if (user.role === 'admin') {
//           return res.redirect('/admin/dashboard');  // Redirect to admin dashboard
//         }

//         if (user.role === 'doctor') {
//           req.session.doctorId = user.id;  // Corrected: Store doctor ID for doctor role
//           return res.redirect('/doctor/dashboard');  // Redirect to doctor dashboard
//         }

//       } else {
//         // If password is incorrect
//         return res.status(401).send('Invalid credentials');
//       }
//     } else {
//       // If no user is found with the given email
//       return res.status(404).send('User not found');
//     }
//   });
// });

// admin dashboard route to create roles in db
app.get('/admin/dashboard', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/login');
  }

  res.render('admin_dashboard');  // Render the admin dashboard
});



// Serve the Create User page when the link is clicked
app.get('/admin/dashboard/create-user', isAdmin, (req, res) => {
  res.render('create_user');  // Render the 'createUser.ejs' page
});

app.post('/admin/dashboard/create-user', isAdmin, (req, res) => {
  let { email, password, role, doctor_id } = req.body; // Use let to allow reassignment

  // First, check if the email exists in the doctors table
  const checkDoctorSql = 'SELECT * FROM doctors WHERE id = ? AND email = ?';

  db.query(checkDoctorSql, [doctor_id, email], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error checking doctor records');
    }

    // If no results are found, that means the email or doctor ID does not exist in the doctors table
    if (results.length === 0) {
      // If doctor doesn't exist, set role to what the user has entered
      role = role || 'admin';  // If no role is provided, default to 'admin'
    } else {
      // If doctor exists, set the role to 'doctor'
      role = 'doctor';
    }

    // Hash the password before inserting into the database
    const hashedPassword = bcrypt.hashSync(password, 10); // 10 is the salt rounds for bcrypt hashing

    // Proceed to create the user in the admin table
    const sql = 'INSERT INTO admin (email, password_hash, role) VALUES (?, ?, ?)';

    db.query(sql, [email, hashedPassword, role], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error creating user');
      }

      // Redirect back to admin dashboard after user creation
      res.redirect('/admin/dashboard');
    });
  });
});
// Route to create a doctor account
// Admin login route POST handler
app.post('/admin/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM Admin WHERE email = ? AND role = "admin"';
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }

    if (results.length > 0) {
      const admin = results[0];
      if (bcrypt.compareSync(password, admin.password_hash)) {
        req.session.adminId = admin.id;  // Store admin ID
        req.session.role = admin.role;   // Store admin role

        // Log session data for debugging
        console.log('Session after login:', req.session);

        return res.redirect('/admin/dashboard');  // Redirect to the admin dashboard
      } else {
        return res.status(401).send('Invalid credentials');
      }
    } else {
      return res.status(404).send('Admin not found');
    }
  });
});


// Admin dashboard route
app.get('/admin/dashboard', isAdmin, (req, res) => {
  // Get the list of patients
  const query = 'SELECT * FROM Patients';
  db.query(query, (err, patients) => {
    if (err) {
      return res.status(500).send('Error fetching patients');
    }
    res.render('admin/dashboard', { patients });
  });
});

// Admin route to add a doctor
app.get('/admin/dashboard/add-doctors', isAdmin, (req, res) => {
  res.render('add_doctor'); // A form to add a new doctor
});

// Define route for adding doctor
app.post('/admin/dashboard/add-doctors', isAdmin, (req, res) => {
  const { first_name, last_name, specialization, email, password, phone, schedule} = req.body;
  
  // Hash the password before storing it
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).send('Error hashing password');

    // Ensure that schedule is a valid JSON (if it's not already a JSON object)
    let scheduleJSON;
    try {
      scheduleJSON = JSON.parse(schedule); // Parse schedule if it's a string
    } catch (parseError) {
      return res.status(400).send('Invalid schedule format');
    }

    // Construct the SQL query to insert the new doctor into the Doctors table
    const query = 'INSERT INTO Doctors (first_name, last_name, specialization, email, password_hash, phone, schedule) VALUES (?, ?, ?, ?, ?, ?, ?)';
    
    // Execute the query
    db.query(query, [first_name, last_name, specialization, email, hashedPassword, phone, JSON.stringify(scheduleJSON)], (err) => {
      if (err) {
        return res.status(500).send('Error adding doctor');
      }
      // Redirect to the admin dashboard after successful insertion
      res.redirect('admin/dashboard');
    });
  });
});







// Admin route to list doctors
app.get('/admin/dashboard/list-doctors', isAdmin, (req, res) => {
  const query = 'SELECT * FROM Doctors';
  db.query(query, (err, doctors) => {
    if (err) {
      return res.status(500).send('Error fetching doctors');
    }
    res.render('list_doctors', { doctors });
  });
});

// Admin route to edit doctor information
app.get('/admin/edit-doctor/:id', isAdmin, (req, res) => {
  const doctorId = req.params.id;
  const query = 'SELECT * FROM Doctors WHERE id = ?';
  db.query(query, [doctorId], (err, doctor) => {
    if (err) {
      return res.status(500).send('Error fetching doctor');
    }
    res.render('edit_doctor', { doctor: doctor[0] });
  });
});

// Admin route to update doctor information
app.post('/admin/edit-doctor/:id', isAdmin, (req, res) => {
  const doctorId = req.params.id;
  const { first_name, last_name, specialization, email, phone, schedule } = req.body;
  const query = 'UPDATE Doctors SET first_name = ?, last_name = ?, specialization = ?, email = ?, phone = ?, schedule = ? WHERE id = ?';
  db.query(query, [first_name, last_name, specialization, email, phone, schedule, doctorId], (err) => {
    if (err) {
      return res.status(500).send('Error updating doctor');
    }
    res.redirect('/admin/dashboard/list-doctors');
  });
});


// Admin route to delete a doctor
app.get('/admin/delete-doctor/:id', isAdmin, (req, res) => {
  const doctorId = req.params.id;

  // SQL query to delete the doctor from the database
  const query = 'DELETE FROM Doctors WHERE id = ?';
  db.query(query, [doctorId], (err, result) => {
    if (err) {
      return res.status(500).send('Error deleting doctor');
    }
    // Redirect back to the list of doctors after successful deletion
    res.redirect('/admin/dashboard/list-doctors');
  });
});


app.get('/current-time', (req, res) => {
  const currentTime = new Date();
  res.send({ current_time: currentTime });
});





// Doctor dashboard route
// Doctor login route
// Doctor login route
// Doctor dashboard route



// Admin login route POST handler
// app.post('/admin/login', (req, res) => {
//   const { email, password } = req.body;

//   // Query the database for the admin with role "doctor"
//   const query = 'SELECT * FROM Admin WHERE email = ? AND role = "doctor"';
//   db.query(query, [email], (err, results) => {
//     if (err) {
//       return res.status(500).send('Database error');
//     }

//     if (results.length > 0) {
//       const doctor = results[0];  // The doctor record

//       // Compare the password with the hashed password stored in the database
//       if (bcrypt.compareSync(password, doctor.password_hash)) {
//         req.session.doctorId = doctor.id;  // Store doctor ID in session
//         req.session.role = doctor.role;    // Store doctor role in session

//         // Log session data for debugging
//         console.log('Session after login:', req.session);

//         // Redirect to the doctor dashboard
//         return res.redirect('/doctor/dashboard');
//       } else {
//         return res.status(401).send('Invalid credentials');
//       }
//     } else {
//       return res.status(404).send('Doctor not found');
//     }
//   });
// });

// Doctor dashboard route
// Assuming this route handles the doctor dashboard
app.get('/doctor/dashboard', (req, res) => {
  // Ensure that the user is a doctor
  if (!req.session.role || req.session.role !== 'doctor') {
    return res.redirect('/login'); // Redirect to login if not a doctor
  }

  // Get the doctor ID from the session
  const doctorId = req.session.doctorId;

  if (!doctorId) {
    return res.status(400).send('Doctor not found');
  }

  // Query the Doctors table to get the doctor's information
  const sqlDoctor = 'SELECT * FROM Doctors WHERE id = ?';
  db.query(sqlDoctor, [doctorId], (err, doctorResults) => {
    if (err) {
      console.error('Error fetching doctor details:', err);
      return res.status(500).send('Database error');
    }

    // If doctor is found, fetch the appointments for the doctor
    if (doctorResults.length > 0) {
      const doctor = doctorResults[0];

      // Query the database to get appointments for the doctor
      const sqlAppointments = `
        SELECT a.*, p.first_name AS patient_first_name, p.last_name AS patient_last_name, a.jitsi_link
        FROM Appointments a
        JOIN Patients p ON a.patient_id = p.id
        WHERE a.doctor_id = ?
        ORDER BY a.appointment_date DESC
      `;
      
      db.query(sqlAppointments, [doctorId], (err, appointmentResults) => {
        if (err) {
          console.error('Error fetching appointments:', err);
          return res.status(500).send('Database error');
        }

        // If no appointments, render empty list message
        if (appointmentResults.length === 0) {
          return res.render('doctor_dashboard', {
            firstName: doctor.first_name,
            lastName: doctor.last_name,
            message: "No appointments scheduled yet."
          });
        }

        // Map over appointments and add Jitsi link
        const appointmentsWithLinks = appointmentResults.map(appointment => {
          const jitsiLink = appointment.jitsi_link;  // Get the stored Jitsi link from the database
          return {
            ...appointment,
            jitsiLink: jitsiLink,  // Add the Jitsi link to the appointment object
          };
        });

        // Render the doctor's dashboard with both the doctor's details and appointments
        res.render('doctor_dashboard', {
          firstName: doctor.first_name,
          lastName: doctor.last_name,
          appointments: appointmentsWithLinks  // Pass the appointments with Jitsi links to the view
        });
      });
    } else {
      return res.status(404).send('Doctor not found');
    }
  });
});



// Route to view and update the doctor's schedule
app.get('/doctor/update-schedule', isDoctor, (req, res) => {
  const doctorId = req.session.doctorId;  // The logged-in doctor's ID from session

  const query = 'SELECT * FROM Doctors WHERE id = ?';
  db.query(query, [doctorId], (err, doctor) => {
    if (err) {
      return res.status(500).send('Error fetching doctor schedule');
    }

    if (doctor.length === 0) {
      return res.status(404).send('Doctor not found');
    }

    res.render('update_schedule', { schedule: doctor[0].schedule });
  });
});

app.post('/doctor/update-schedule', isDoctor, (req, res) => {
  const doctorId = req.session.doctorId;  // Get the doctor ID from the session
  const { schedule } = req.body;  // Assume schedule is a JSON object

  const query = 'UPDATE Doctors SET schedule = ? WHERE id = ?';
  db.query(query, [JSON.stringify(schedule), doctorId], (err) => {
    if (err) {
      return res.status(500).send('Error updating schedule');
    }
    res.redirect('/doctor/dashboard');  // Redirect to the dashboard after updating
  });
});

// Route to update doctor's profile
app.get('/doctor/update-profile', isDoctor, (req, res) => {
  const doctorId = req.session.doctorId;  // Get doctor ID from session

  const query = 'SELECT * FROM Doctors WHERE id = ?';
  db.query(query, [doctorId], (err, doctor) => {
    if (err) {
      return res.status(500).send('Error fetching doctor profile');
    }
    res.render('update_profile', { doctor: doctor[0] });
  });
});

app.post('/doctor/update-profile', isDoctor, (req, res) => {
  const doctorId = req.session.doctorId;  // Get doctor ID from session
  const { first_name, last_name, specialization, email, phone } = req.body;

  const query = 'UPDATE Doctors SET first_name = ?, last_name = ?, specialization = ?, email = ?, phone = ? WHERE id = ?';
  db.query(query, [first_name, last_name, specialization, email, phone, doctorId], (err) => {
    if (err) {
      return res.status(500).send('Error updating doctor profile');
    }
    res.redirect('/doctor/dashboard');  // Redirect to the dashboard after updating
  });
});

// Start the server
server.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
