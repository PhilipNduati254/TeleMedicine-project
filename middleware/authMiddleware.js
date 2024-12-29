module.exports = {
  // Middleware to ensure the user is an admin
  isAdmin: (req, res, next) => {
    console.log('Session (Admin):', req.session);  // Log the entire session for debugging
    if (req.session.role !== 'admin') {
      return res.redirect('/login'); // Redirect if not an admin
    }
    next();  // Continue if admin
  },

  // Middleware to ensure the user is a doctor
  isDoctor: (req, res, next) => {
    console.log('Session (Doctor):', req.session);  // Log session data for debugging

    // Ensure that the session has both the doctor role and a valid doctorId
    if (req.session.role !== 'doctor' || !req.session.doctorId) {
      return res.redirect('/login');  // Redirect to admin login if not a doctor or no doctorId in session
    }

    next();  // Continue if doctor
  }
};

