// Archivo actualizado para manejar perfil e inicio y nuevas funcionalidades

// Importación de módulos necesarios
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

// Inicialización
const app = express();
const PORT = process.env.PORT || 3000; // Puerto dinámico para Render

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Conexión a MongoDB
const uri = "mongodb+srv://JUANLU:Esjupevies5..@linqrup.x4j10.mongodb.net/linqrup?retryWrites=true&w=majority";
mongoose.connect(uri, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
    .then(() => console.log("Conexión exitosa a MongoDB"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

// Modelos
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bio: { type: String, default: "" },
    profilePicture: { type: String, default: "" },
    socialLinks: [{ type: String }],
    posts: [
        {
            title: String,
            content: String,
            createdAt: { type: Date, default: Date.now }
        }
    ],
    qrScans: [String],
    notifications: [String]
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

// Ruta para el perfil de usuario
app.get('/api/perfil', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).send('Token no proporcionado.');

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, 'secreto');

        const user = await User.findById(decoded.id).select('-password');
        if (!user) return res.status(404).send('Usuario no encontrado.');

        res.status(200).json(user);
    } catch (error) {
        console.error("Error al cargar el perfil:", error);
        res.status(500).send('Error al cargar el perfil.');
    }
});

// Ruta para la página de inicio
app.get('/api/inicio', async (req, res) => {
    try {
        const posts = await Post.find().populate('author', 'username');
        res.status(200).json(posts);
    } catch (error) {
        console.error("Error al cargar datos de inicio:", error);
        res.status(500).send('Error al cargar datos de inicio.');
    }
});

// Ruta para crear un nuevo usuario (registro)
app.post('/api/register', async (req, res) => {
    const { username, password, bio, profilePicture, socialLinks } = req.body;

    if (!username || !password) {
        return res.status(400).send('Faltan datos obligatorios.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, bio, profilePicture, socialLinks });
        await newUser.save();
        res.status(201).send('Usuario registrado correctamente.');
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).send('El nombre de usuario ya está en uso.');
        } else {
            res.status(500).send('Error al registrar usuario.');
        }
    }
});

// Ruta para inicio de sesión
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).send('Usuario no encontrado.');

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).send('Contraseña incorrecta.');

        const token = jwt.sign({ id: user._id, username: user.username }, 'secreto', { expiresIn: '1h' });
        res.status(200).send({ message: 'Inicio de sesión exitoso.', token });
    } catch (error) {
        res.status(500).send('Error en el inicio de sesión.');
    }
});

// Ruta para crear publicación
app.post('/api/posts', async (req, res) => {
    const { username, title, content } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).send("Usuario no encontrado");

        user.posts.push({ title, content });
        await user.save();

        res.status(201).json({ message: "Publicación creada exitosamente" });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al crear publicación");
    }
});

// Ruta para obtener notificaciones
app.get('/api/notifications', async (req, res) => {
    try {
        const user = await User.findOne({ username: "usuario_demo" }); // Sustituir con autenticación real
        if (!user) return res.status(404).send("Usuario no encontrado");

        res.status(200).json(user.notifications);
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al obtener notificaciones");
    }
});

// Ruta para estadísticas del usuario
app.get('/api/statistics', async (req, res) => {
    try {
        const user = await User.findOne({ username: "usuario_demo" }); // Sustituir con autenticación real
        if (!user) return res.status(404).send("Usuario no encontrado");

        const stats = {
            posts: user.posts.length,
            reactions: 0, // Implementar lógica para reacciones
            qrScans: user.qrScans.length
        };

        res.status(200).json(stats);
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al obtener estadísticas");
    }
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor iniciado en el puerto ${PORT}`);
});
