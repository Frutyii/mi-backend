const { MongoClient, ServerApiVersion } = require('mongodb');

// URI de conexión a MongoDB
const uri = "mongodb+srv://JUANLU:<Esjupevies5..>@linqrup.x4j10.mongodb.net/?retryWrites=true&w=majority&appName=Linqrup";

// Crear un cliente de MongoDB con opciones para API estable
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1, // Especifica la versión estable del API
    strict: true,                 // Activa restricciones estrictas
    deprecationErrors: true,      // Activa advertencias de funciones obsoletas
  },
});

async function run() {
  try {
    // Conectar el cliente al servidor
    await client.connect();
    // Enviar un ping para confirmar la conexión
    await client.db("admin").command({ ping: 1 });
    console.log("¡Conexión establecida correctamente con MongoDB!");
  } catch (err) {
    console.error("Error al conectar a MongoDB:", err);
  } finally {
    // Asegurarse de cerrar la conexión después de usarla
    await client.close();
  }
}

// Ejecutar la función principal
run().catch(console.error);

