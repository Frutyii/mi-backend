// Importación de módulos necesarios
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

// Inicialización
const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Conexión a MongoDB
const uri = "mongodb+srv://JUANLU:Esjupevies5..@linqrup.x4j10.mongodb.net/linqrup?retryWrites=true&w=majority";
mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
    .then(() => console.log("Conexión exitosa a MongoDB"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

// Modelo de Usuario
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    bio: { type: String, default: "" },
    profilePicture: { type: String, default: "" },
    socialLinks: [{ type: String }], // Enlaces a redes sociales
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Modelo de Publicación
const postSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const Post = mongoose.model('Post', postSchema);

// Rutas
app.get('/', (req, res) => {
    res.send('¡Bienvenido a mi API! Las rutas disponibles son: /register, /login, /profile, /posts.');
});

// Registro de usuario
app.post('/register', async (req, res) => {
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

// Inicio de sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).send('Usuario no encontrado.');
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send('Contraseña incorrecta.');
        }

        const token = jwt.sign({ username, id: user._id }, 'secreto', { expiresIn: '1h' });
        res.status(200).send({ message: 'Inicio de sesión exitoso.', token });
    } catch (error) {
        res.status(500).send('Error en el inicio de sesión.');
    }
});

// Perfil de usuario
app.get('/profile', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send('Token no proporcionado.');
    }

    const token = authHeader.split(' ')[1];
    try {
        const user = jwt.verify(token, 'secreto');
        res.status(200).send(`Bienvenido al perfil, ${user.username}.`);
    } catch (error) {
        res.status(401).send('Token inválido.');
    }
});

// Crear publicación
app.post('/posts', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send('Token no proporcionado.');
    }

    const token = authHeader.split(' ')[1];
    try {
        const user = jwt.verify(token, 'secreto');
        const { title, content } = req.body;
        if (!title || !content) {
            return res.status(400).send('Título y contenido son obligatorios.');
        }

        const newPost = new Post({ title, content, author: user.id });
        await newPost.save();
        res.status(201).send('Publicación creada con éxito.');
    } catch (error) {
        res.status(500).send('Error al crear la publicación.');
    }
});

// Obtener publicaciones
app.get('/posts', async (req, res) => {
    try {
        const posts = await Post.find().populate('author', 'username');
        res.status(200).send(posts);
    } catch (error) {
        res.status(500).send('Error al obtener publicaciones.');
    }
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
