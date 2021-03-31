// Añadimos los módulos necesarios
const FS = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const JWT = require('jsonwebtoken');
const middlewares = jsonServer.defaults()

// Servidor Express
const server = jsonServer.create();

// Enrutador Express
const router = jsonServer.router('./db.json');

// Creamos un JSON con los usuarios (03f996214fba4a1d05a68b18fece8e71 == MD5 Hash 'usuarios' )
const userdb = JSON.parse(FS.readFileSync('./03f996214fba4a1d05a68b18fece8e71.json', 'UTF-8'));

// Middlewares predeterminados (logger, static, cors y no-cache)
server.use(middlewares)

// Parseo del body
server.use(jsonServer.bodyParser);

// Configuración TOKEN y duración
const SECRET_KEY = 'zxcasdqwe098765';
const expiresIn = '1h';

// Crear un TOKEN desde un payload 
createToken = (payload) => JWT.sign(payload, SECRET_KEY, { expiresIn });

// Verificar el TOKEN 
verifyToken = (token) => JWT.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err);

// Comprobamos si el usuario existe en nuestra 'base de datos'
isAuthenticated = ({ email, password }) => userdb.users.findIndex(user => user.email === email && user.password === password) !== - 1;

// Creamos un ENDPOINT para comprobar si el usuario existe y poder crear y enviar un TOKEN
server.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (isAuthenticated({ email, password }) === false) {
        const status = 401;
        const message = 'Contraseña y/o password incorrectos';
        res.status(status).json({ status, message })
        console.log(message);
        return;
    }
    const access_token = createToken({ email, password });
    res.status(200).json({ access_token })
});

// Añadir un middleware Express que verifique si el encabezado de autorización.
// Luego verificara si el token es válido para todas las rutas, excepto la ruta anterior, 
// ya que esta es la que usamos para iniciar sesión en los usuarios.
server.use(/^(?!\/auth).*$/, (req, res, next) => {
    setTimeout(()=>{
        if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
            const status = 401;
            const message = 'Header con autorización incorrecta';
            res.status(status).json({ status, message });
            console.log(message);
            return;
        }
        try {
            verifyToken(req.headers.authorization.split(' ')[1]);
            next();
        } catch (err) {
            const status = 401;
            const message = 'Error: TOKEN de acceso no válido';
            res.status(status).json({ status, message });
            console.log(message);
        }
    }, 0)
})
server.use(router);

server.listen(process.env.PORT || 3000, () => {
    console.log('API REST FUNCIONANDO')
});