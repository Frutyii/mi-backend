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
require('dotenv').config();

// Inicialización
const app = express();
const PORT = process.env.PORT || 3000; // Puerto dinámico para Render

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


// Conexión a MongoDB
const uri = process.env.MONGODB_URI;
mongoose.connect(uri, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
    .then(() => console.log("Conexión exitosa a MongoDB"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

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
    clientID: 'TU_CLIENT_ID',
    clientSecret: 'TU_CLIENT_SECRET',
    callbackURL: 'http://localhost:3000/auth/google/callback'
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
    coverPhoto: { type: String, default: "" }, // Nuevo campo para la foto de portada
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

const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);

// Modelo de comentario
const commentSchema = new mongoose.Schema({
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    createdAt: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', commentSchema);

// Modelo de reacciones
const reactionSchema = new mongoose.Schema({
    type: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    createdAt: { type: Date, default: Date.now }
});

const Reaction = mongoose.model('Reaction', reactionSchema);

// Modelo de seguimiento de usuarios
const followSchema = new mongoose.Schema({
    follower: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    following: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

const Follow = mongoose.model('Follow', followSchema);

// Modelo de vídeo
const videoSchema = new mongoose.Schema({
    url: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    comments: [
        {
            content: String,
            author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
            createdAt: { type: Date, default: Date.now }
        }
    ],
    reactions: [
        {
            type: String,
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
            createdAt: { type: Date, default: Date.now }
        }
    ]
});

const Video = mongoose.model('Video', videoSchema);

// Validación de datos con Joi
const registerSchema = Joi.object({
    username: Joi.string().min(3).max(30).required(),
    password: Joi.string().min(6).required(),
    bio: Joi.string().max(500),
    profilePicture: Joi.string().uri(),
    socialLinks: Joi.array().items(Joi.string().uri())
});

// Ruta para el perfil de usuario
app.get('/api/perfil', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, 'secreto');

        const user = await User.findById(decoded.id).select('-password');
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        res.status(200).json(user);
    } catch (error) {
        console.error("Error al cargar el perfil:", error);
        res.status(500).json({ error: 'Error al cargar el perfil.' });
    }
});

// Ruta para la página de inicio
app.get('/api/inicio', async (req, res) => {
    try {
        const posts = await Post.find().populate('author', 'username');
        res.status(200).json(posts);
    } catch (error) {
        console.error("Error al cargar datos de inicio:", error);
        res.status(500).json({ error: 'Error al cargar datos de inicio.' });
    }
});

// Ruta para crear un nuevo usuario (registro)
app.post('/api/register', async (req, res) => {
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const { username, password, bio, profilePicture, socialLinks } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Faltan datos obligatorios.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, bio, profilePicture, socialLinks });
        await newUser.save();
        res.status(201).json({ message: 'Usuario registrado correctamente.' });
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).json({ error: 'El nombre de usuario ya está en uso.' });
        } else {
            res.status(500).json({ error: 'Error al registrar usuario.' });
        }
    }
});

// Ruta para inicio de sesión
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ error: 'Contraseña incorrecta.' });

        const token = jwt.sign({ id: user._id, username: user.username }, 'secreto', { expiresIn: '1h' });
        res.status(200).json({ message: 'Inicio de sesión exitoso.', token });
    } catch (error) {
        res.status(500).json({ error: 'Error en el inicio de sesión.' });
    }
});

// Ruta para solicitar restablecimiento de contraseña
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hora
        await user.save();

        const mailOptions = {
            to: user.email,
            from: 'tu-email@gmail.com',
            subject: 'Restablecimiento de contraseña',
            text: `Recibiste este correo porque tú (o alguien más) solicitó restablecer la contraseña de tu cuenta.\n\n` +
                `Haz clic en el siguiente enlace, o pégalo en tu navegador para completar el proceso:\n\n` +
                `http://localhost:3000/reset-password/${token}\n\n` +
                `Si no solicitaste esto, ignora este correo y tu contraseña permanecerá sin cambios.\n`
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) return res.status(500).json({ error: 'Error al enviar el correo electrónico.' });
            res.status(200).json({ message: 'Correo de restablecimiento de contraseña enviado.' });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al solicitar restablecimiento de contraseña.' });
    }
});

// Ruta para restablecer la contraseña
app.post('/api/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });
        if (!user) return res.status(400).json({ error: 'Token inválido o expirado.' });

        const { password } = req.body;
        user.password = await bcrypt.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Contraseña restablecida correctamente.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al restablecer la contraseña.' });
    }
});

// Ruta para subir foto de perfil
app.post('/api/upload-photo', upload.single('photo'), async (req, res) => {
    try {
        const userId = req.body.userId;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        // Guardar la URL de la imagen en el perfil del usuario
        user.profilePicture = `/uploads/${req.file.filename}`;
        await user.save();

        res.status(200).json({ message: 'Foto subida exitosamente.', profilePicture: user.profilePicture });
    } catch (error) {
        console.error('Error al subir la foto:', error);
        res.status(500).json({ error: 'Error al subir la foto.' });
    }
});

// Ruta para subir vídeos
app.post('/api/upload-video', uploadVideo.single('video'), async (req, res) => {
    try {
        const { userId, title, description } = req.body;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const newVideo = new Video({
            url: `/uploads/videos/${req.file.filename}`,
            title,
            description,
            author: user._id
        });
        await newVideo.save();

        res.status(200).json({ message: 'Vídeo subido exitosamente.', video: newVideo });
    } catch (error) {
        console.error('Error al subir el vídeo:', error);
        res.status(500).json({ error: 'Error al subir el vídeo.' });
    }
});

// Ruta para agregar un comentario a un vídeo
app.post('/api/videos/:videoId/comments', async (req, res) => {
    const { content } = req.body;
    const { videoId } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'secreto');

    try {
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const video = await Video.findById(videoId);
        if (!video) return res.status(404).json({ error: 'Vídeo no encontrado.' });

        video.comments.push({ content, author: user._id });
        await video.save();

        res.status(201).json({ message: 'Comentario agregado exitosamente.', comments: video.comments });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al agregar comentario.' });
    }
});

// Ruta para obtener comentarios de un vídeo
app.get('/api/videos/:videoId/comments', async (req, res) => {
    const { videoId } = req.params;
    try {
        const video = await Video.findById(videoId).populate('comments.author', 'username');
        if (!video) return res.status(404).json({ error: 'Vídeo no encontrado.' });

        res.status(200).json(video.comments);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener comentarios.' });
    }
});

// Ruta para agregar una reacción a un vídeo
app.post('/api/videos/:videoId/reactions', async (req, res) => {
    const { type } = req.body;
    const { videoId } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'secreto');

    try {
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const video = await Video.findById(videoId);
        if (!video) return res.status(404).json({ error: 'Vídeo no encontrado.' });

        video.reactions.push({ type, user: user._id });
        await video.save();

        res.status(201).json({ message: 'Reacción agregada exitosamente.', reactions: video.reactions });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al agregar reacción.' });
    }
});

// Ruta para obtener reacciones de un vídeo
app.get('/api/videos/:videoId/reactions', async (req, res) => {
    const { videoId } = req.params;
    try {
        const video = await Video.findById(videoId).populate('reactions.user', 'username');
        if (!video) return res.status(404).json({ error: 'Vídeo no encontrado.' });

        res.status(200).json(video.reactions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener reacciones.' });
    }
});

// Servir archivos estáticos desde la carpeta "uploads"
app.use('/uploads', express.static('uploads'));

// Ruta para crear publicación
app.post('/api/posts', async (req, res) => {
    const { username, title, content } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

        user.posts.push({ title, content });
        await user.save();

        res.status(201).json({ message: "Publicación creada exitosamente" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al crear publicación" });
    }
});

// Ruta para agregar un comentario a una publicación
app.post('/api/posts/:postId/comments', async (req, res) => {
    const { content } = req.body;
app.post('/api/posts', async (req, res) => {
    const { username, title, content } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

        user.posts.push({ title, content });
        await user.save();

        res.status(201).json({ message: "Publicación creada exitosamente" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al crear publicación" });
    }
});

// Ruta para agregar un comentario a una publicación
app.post('/api/posts/:postId/comments', async (req, res) => {
    const { content } = req.body;
    const { postId } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'secreto');

    try {
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

        const newComment = new Comment({ content, author: user._id, post: post._id });
        await newComment.save();

        res.status(201).json({ message: 'Comentario agregado exitosamente.', comment: newComment });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al agregar comentario.' });
    }
});

// Ruta para obtener comentarios de una publicación
app.get('/api/posts/:postId/comments', async (req, res) => {
    const { postId } = req.params;
    try {
        const comments = await Comment.find({ post: postId }).populate('author', 'username');
        res.status(200).json(comments);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener comentarios.' });
    }
});

// Ruta para agregar una reacción a una publicación
app.post('/api/posts/:postId/reactions', async (req, res) => {
    const { type } = req.body;
    const { postId } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'secreto');

    try {
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

        const newReaction = new Reaction({ type, user: user._id, post: post._id });
        await newReaction.save();

        res.status(201).json({ message: 'Reacción agregada exitosamente.', reaction: newReaction });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al agregar reacción.' });
    }
});

// Ruta para obtener reacciones de una publicación
app.get('/api/posts/:postId/reactions', async (req, res) => {
    const { postId } = req.params;
    try {
        const reactions = await Reaction.find({ post: postId }).populate('user', 'username');
        res.status(200).json(reactions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener reacciones.' });
    }
});

// Ruta para seguir a un usuario
app.post('/api/follow/:userId', async (req, res) => {
    const { userId } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado.' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'secreto');

    try {
        const follower = await User.findById(decoded.id);
        if (!follower) return res.status(404).json({ error: 'Usuario no encontrado.' });

        const following = await User.findById(userId);
        if (!following) return res.status(404).json({ error: 'Usuario a seguir no encontrado.' });

        const newFollow = new Follow({ follower: follower._id, following: following._id });
        await newFollow.save();

        res.status(201).json({ message: 'Usuario seguido exitosamente.', follow: newFollow });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al seguir usuario.' });
    }
});

// Ruta para obtener los seguidores de un usuario
app.get('/api/users/:userId/followers', async (req, res) => {
    const { userId } = req.params;
    try {
        const followers = await Follow.find({ following: userId }).populate('follower', 'username');
        res.status(200).json(followers);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener seguidores.' });
    }
});

// Ruta para obtener los usuarios seguidos por un usuario
app.get('/api/users/:userId/following', async (req, res) => {
    const { userId } = req.params;
    try {
        const following = await Follow.find({ follower: userId }).populate('following', 'username');
        res.status(200).json(following);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener usuarios seguidos.' });
    }
});

// Ruta para obtener notificaciones
app.get('/api/notifications', async (req, res) => {
    try {
        const user = await User.findOne({ username: "usuario_demo" }); // Sustituir con autenticación real
        if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

        res.status(200).json(user.notifications);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al obtener notificaciones" });
    }
});

// Ruta para estadísticas del usuario
app.get('/api/statistics', async (req, res) => {
    try {
        const user = await User.findOne({ username: "usuario_demo" }); // Sustituir con autenticación real

        if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

        const stats = {
            posts: user.posts.length,
            reactions: 0, // Implementar lógica para reacciones
            qrScans: user.qrScans.length
        };

        res.status(200).json(stats);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al obtener estadísticas" });
    }
});

// Ruta para autenticación con Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

// Ruta de callback de Google
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/perfil');
});

// Configuración de HTTPS
app.use((req, res, next) => {
    if (req.secure) {
        next();
    } else {
        res.redirect(`https://${req.headers.host}${req.url}`);
    }
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
// Cierra el bloque principal del archivo
});