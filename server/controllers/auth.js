import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import User from '../models/User.js'

/* REGISTER USER */
export const register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      picturePath,
      friends,
      location,
      occupation,
    } = req.body;

    /* Check if user already exists */
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    /* Hass the password */
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    /* Create a new user*/
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      picturePath,
      friends,
      location,
      occupation,
      viewedProfile: Math.floor(Math.random() * 10000),
      impressions: Math.floor(Math.random() * 10000),
    });

    /* Save the new user to the database */
    const savedUser = await newUser.save();

    /* Send a success response */
    res.status(200).json({ message: 'User registered successfully', user: savedUser });
  } catch (err) {
    /* Handle any errors that occur during registration */
    res.status(500).json({ message: 'Registration failed', error: err.message });
  }
};


/* LOG IN */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    /* Check if the user exists */
    const user = await User.findOne({ email: email });
    if (!user) return res.status(400).json({ message: "User does not exist." });

    /* Compare password */
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });

    /* Generate JWT */
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    delete user.password;
    res.status(200).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};