const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const BearerStrategy = require('passport-http-bearer').Strategy
const jwt = require('jsonwebtoken')

const Usuario = require('./usuarios-modelo')
const { InvalidArgumentError } = require('../erros')
const bcrypt = require('bcrypt')

function verificaUsuario(usuario) {
  if(!usuario) {
    throw new InvalidArgumentError('Não existe usúario com este email')
  }
}

async function verificaSenha(senha, senhaHash) {
  console.log(senha, senhaHash)
  const senhaValida = await bcrypt.compare(senha, senhaHash)
  if (!senhaValida) {
    throw new InvalidArgumentError('E-mail ou senha inválidos')
  }
}

passport.use(
  new LocalStrategy({
    usernameField: 'email',
    passwordField: 'senha',
    session: false
  }, async (email, senha, done) => {
    try {
      const usuario = await Usuario.buscaPorEmail(email)
      verificaUsuario(usuario)
      verificaSenha(senha, usuario.senhaHash)

      done(null, usuario)
    } catch (error) {
      done(error)
    }
  })
)

passport.use(
  new BearerStrategy((token, done) => {
    try {
      const payload = jwt.verify(token, process.env.CHAVE_JWT)
      const usuario = Usuario.buscaPorId(payload.id)
      done(null, usuario)
    } catch (error) {
      done(error)
    }
  })
)