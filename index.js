const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

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
    serverSelectionTimeoutMS: 5000, // Tiempo máximo para encontrar el servidor MongoDB
    socketTimeoutMS: 45000,        // Tiempo máximo para operaciones en el socket
})
    .then(() => console.log("Conexión exitosa a MongoDB"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

// Modelo de usuario para MongoDB
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}, { timestamps: true }); // Añade timestamps de creación y actualización

const User = mongoose.model('User', userSchema);

// Ruta principal
app.get('/', (req, res) => {
    res.send('¡Bienvenido a mi API! Las rutas disponibles son: /register, /login y /profile.');
});

// Ruta: Registro de usuarios
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Faltan datos obligatorios.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
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

// Ruta: Inicio de sesión
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

        const token = jwt.sign({ username }, 'secreto', { expiresIn: '1h' });
        res.status(200).send({ message: 'Inicio de sesión exitoso.', token });
    } catch (error) {
        res.status(500).send('Error en el inicio de sesión.');
    }
});

// Ruta: Perfil de usuario
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

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
