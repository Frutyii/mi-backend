// Importación de módulos necesarios
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const socketIo = require('socket.io');
require('dotenv').config(); // Asegurar carga de variables de entorno

// Inicialización
const app = express();
const PORT = process.env.PORT || 3000; // Puerto dinámico para Render
const SECRET = process.env.JWT_SECRET || 'defaultSecret';

// Middleware
app.use(bodyParser.json());
app.use(cors({
    origin: process.env.CORS_ORIGIN
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(helmet());

// Límite de tasa para proteger contra ataques de fuerza bruta
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100 // límite de 100 solicitudes por IP
});
app.use(limiter);

// Configuración de almacenamiento local para Multer
const storage = multer.diskStorage({
    destination: 'uploads/', // Carpeta donde se almacenarán las imágenes
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`); // Nombre único para cada archivo
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limitar tamaño a 5 MB
    fileFilter: (req, file, cb) => {
        const fileTypes = /jpeg|jpg|png/;
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = fileTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Solo se permiten archivos JPEG, JPG y PNG.'));
        }
    }
});

const uploadVideo = multer({
    storage: storage, // Opciones específicas para videos si las necesitas
    limits: { fileSize: 50 * 1024 * 1024 } // Ejemplo: Limitar a 50 MB para videos
});

// Middleware de autenticación
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Token inválido.' });
    }
};

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
    .then(() => console.log("Conexión exitosa a MongoDB"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

// Habilitar logs detallados de Mongoose para depuración
mongoose.set('debug', true);

// Configuración de Nodemailer para enviar correos electrónicos
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Configuración de Passport para Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
}, async (token, tokenSecret, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = new User({
                googleId: profile.id,
                username: profile.displayName,
                profilePicture: profile.photos[0].value
            });
            await user.save();
        }
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Modelos
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bio: { type: String, default: "" },
    profilePicture: { type: String, default: "" },
    coverPhoto: { type: String, default: "" },
    socialLinks: [{ type: String }],
    posts: [
        {
            title: String,
            content: String,
            createdAt: { type: Date, default: Date.now }
        }
    ],
    qrScans: [String],
    notifications: [String],
    resetPasswordToken: String,
    resetPasswordExpires: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Rutas actualizadas con middleware
app.get('/api/perfil', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        res.status(200).json(user);
    } catch (error) {
        console.error("Error al cargar el perfil:", error);
        res.status(500).json({ error: 'Error al cargar el perfil.' });
    }
});

// Ruta de autenticación con Google
app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/login',
    session: false
}), (req, res) => {
    const token = jwt.sign({ id: req.user.id }, SECRET, { expiresIn: '1h' });
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/?token=${token}`);
});

// Ruta de ejemplo
app.get('/api/secure-route', authenticate, (req, res) => {
    res.status(200).json({ message: 'Ruta protegida, usuario autenticado.', user: req.user });
});

// Configuración de Socket.io para notificaciones en tiempo real
const server = app.listen(PORT, () => {
    console.log(`Servidor iniciado en el puerto ${PORT}`);
});

const io = socketIo(server);

io.on('connection', (socket) => {
    console.log('Usuario conectado');

    socket.on('disconnect', () => {
        console.log('Usuario desconectado');
    });

    socket.on('sendNotification', (data) => {
        io.emit('receiveNotification', data);
    });
});
