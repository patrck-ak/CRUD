require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const User = require('./models/User')

const app = express()
const port = 3000;

// configurar reposta json
app.use(express.json())

// Public Route (Página inicial)
app.get('/', (req, res) => {
  res.status(200).json({msg: "Bem-Vindo a nossa API :)"})
})

// validar usuario
app.post('/auth/login', async(req, res) => {
  const {name, password} = req.body

  if(!name) { 
    return res.status(422).json({msg: 'Nome é obrigatorio!'})
  }
  if(!password) { 
    return res.status(422).json({msg: 'Senha é obrigatoria!'})
  }

  // checar usuario
  const user = await User.findOne({name: name})
  if(!user) {
    return res.status(404).json({msg: 'Usuário não encontrado.'})
  }

  const checkPassword = await bcrypt.compare(password, user.password)
  if(!checkPassword) {
    return res.status(422).json({msg: 'Senha incorreta.'})
  }

  try {
    const secret = process.env.SECRET
    const token = jwt.sign({id: user._id}, secret)

    res.status(200).json({msg: 'logado com sucesso.', token})

  } catch (err) {
    console.log(err)
    res.status(500).json({msg: err})
  }

})


// registrar usuario DB
app.post('/auth/register', async(req, res) => {
  const {name, email, password, confirmpassword, level} = req.body
  // validações

  if(!name) { 
    return res.status(422).json({msg: 'Nome é obrigatorio!'})
  }
  if(!email) { 
    return res.status(422).json({msg: 'E-Mail é obrigatorio!'})
  }
  if(!password) { 
    return res.status(422).json({msg: 'Senha é obrigatoria!'})
  }
  if(password !== confirmpassword){
    return res.status(442).json({msg: 'Senhas não batem.'})
  }
  if(!level) {
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
 
  // criptar senha DB
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // criar usuario na DB
  const user = new User({
    name,
    email,
    password: passwordHash,
  })

  try { // tenta criar um usuario
    await user.save()
    res.status(201).json({msg: "usuario criado com sucesso."})

  } catch (error) { // retorna erro caso tenha algum
    console.log(error)
    res.status(500).json({msg: error})
  }

})

// database user
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.zausybw.mongodb.net/`)
    .then(app.listen(port, () => {console.log('banco conectado!\n' + 'app rodando na porta ' + port)}))
    .catch((err) => {console.log(err)})