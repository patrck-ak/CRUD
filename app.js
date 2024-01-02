require('dotenv').config()

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');

// importar models do moongose
const { access } = require('fs');
const User = require('./models/User');

// configuração server
const app = express();
const port = 3000;
const internalServerError = 'Erro interno, tente novamente mais tarde.'


// configuração render
app.engine("html", require("ejs").renderFile);
app.set("view engine", "html");
app.use("/public", express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "/views"));

// configuração bodyparser
app.use(bodyParser.urlencoded({ extended: true }));

// configuração reposta json
app.use(express.json());

//! Public Route (Página inicial)
app.get('/', (req, res) => {
  res.render('redirect')
})

//! Private Route (Página de usuario logado)
app.get('/users/:id', checkToken, async(req, res) => {
  const id = req.params.id

  //! checar usuario
  try {
    const user = await User.findById(id, '-password')
    if(!user) {
      return res.status(404).json({msg: 'Usuário não encontrado.'})
    }
    res.status(200).json({msg: user})
    res.render('index')
  } catch (err) {
    console.log(err)
    res.status(500).json({msg: internalServerError})
  }
})

// função para verificar token na rota privada
function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  //* pega o retorno do token e separa nome | valor e retorna valor
  const token = authHeader && authHeader.split(" ")[1] 
  if(!token){
    return res.status(401).json({msg: 'Acesso negado.'})
  }

  try {
    const secret = process.env.secret
    jwt.verify(token, secret)
    next()
  } catch (err) {
    return res.status(400).json({msg: 'Token Inválido.'})
  }
}


//! Validar usuario
app.get('/auth/login', async(req, res) => {
  const secret = process.env.SECRET
  const token = jwt.sign({id: user._id}, secret)

  res.render('login')
})

app.post('/auth/login', async(req, res) => {
  const {name, password} = req.body

  if(!name) { 
    return res.status(422).json({msg: 'Nome é obrigatorio!'})
  } if(!password) { 
    return res.status(422).json({msg: 'Senha é obrigatoria!'})
  }
  // Checar usuario
  const user = await User.findOne({name: name})
  if(!user) {
    return res.status(404).json({msg: 'Usuário não encontrado.'})
  }
  // Campara as senhas senha
  const checkPassword = await bcrypt.compare(password, user.password)
  if(!checkPassword) {
    return res.status(422).json({msg: 'Senha incorreta.'})
  }
  try {
    const secret = process.env.SECRET
    const token = jwt.sign({id: user._id}, secret)
    res.status(200).cookie('access_token', 'Bearer ' + token).render('index')
  } catch (err) {
    console.error(err)
    res.status(500).json({msg: internalServerError})
    
  }})


//! Registrar usuario DB
app.post('/auth/register', async(req, res) => {
  const {name, email, password, confirmpassword, level} = req.body
  // validações

  if(!name) { 
    return res.status(422).json({msg: 'Nome é obrigatorio!'})
  } if(!email) { 
    return res.status(422).json({msg: 'E-Mail é obrigatorio!'})
  } if(!password) { 
    return res.status(422).json({msg: 'Senha é obrigatoria!'})
  } if(password !== confirmpassword){
    return res.status(442).json({msg: 'Senhas não batem.'})
  } if(!level) {
    return res.status(442).json({msg: 'Nivel de permissão é necessário.'})
  }

  // checar caso já exista um usuario
  const mailExists = await User.findOne({email: email})
  const userExists = await User.findOne({name: name})

  if(mailExists) {
    return res.status(422).json({msg: "Email já cadastrado"})
  }
  if(userExists) {
    return res.status(422).json({msg: "Usuário já cadastrado"})
  }
 
  //! criptar senha DB
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  //! criar usuario na DB
  const user = new User({
    name,
    email,
    password: passwordHash,
    level,
  })

  try { // tenta criar um usuario
    await user.save()
    res.status(201).json({msg: "usuario criado com sucesso."})

  } catch (error) { // retorna erro caso tenha algum
    console.log(error)
    res.status(500).json({msg: internalServerError})
  }
})

//! Buscar usuario
app.post('/user/login/search', async(req, res) => {
  const {name, searched} = req.body
  const user = await User.findOne({name: name})
  const search = await User.findOne({name: searched})

  try {
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(search.password, salt)

    res.json({msg: 'usuario encontrado: ' + search.name + ' ' + passwordHash})
  } catch (err) {
    console.log(err)
    res.status(500).json({msg: internalServerError})
  }
})

//* Database user
//! ALTERE NO .ENV
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

//! Conexão a DB (dados no .env)
mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.zausybw.mongodb.net/`)
    .then(app.listen(port, () => {console.log('banco conectado!\n' + 'app rodando na porta ' + port)}))
    .catch((err) => {console.log(err)})