import Fastify from 'fastify'
import { Pool } from 'pg'
import cors from '@fastify/cors'
import dotenv from 'dotenv'
import jwt from '@fastify/jwt'
import bcrypt from 'bcrypt'

dotenv.config()

const sql = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: "localhost",
    port: 5432,
    database: process.env.DB_DATABASE
})

const servidor = Fastify()

servidor.register(cors, {
    origin: '*',
    methods: ['PUT', 'POST', 'DELETE', 'GET']
})

servidor.register(jwt, {
    secret: process.env.JWT_SECRET,
    sign: { expiresIn: '1h' }
})

servidor.get('/usuarios', async (request, reply) => {
    const resultado = await sql.query('select * from usuario')
    return resultado.rows
})

servidor.post('/usuarios', async (request, reply) => {
    const body = request.body

    if (!body || !body.nome || !body.email || !body.senha) {
        return reply.status(400).send({ message: "nome, email e senha são obrigatórios!" })
    }

    const salt = 10
    const senhaHash = await bcrypt.hash(body.senha, salt)

    await sql.query('INSERT INTO usuario (nome, email, senha) VALUES ($1, $2, $3)', [body.nome, body.email, senhaHash])
    reply.status(201).send({ message: 'Usuário Criado!' })
})

servidor.post('/login', async (request, reply) => {
    const body = request.body

    if (!body || !body.email || !body.senha) {
        return reply.status(400).send({ error: "email e senha obrigatórios!" })
    }

    const usuario = await sql.query('select * from usuario where email = $1', [body.email])

    if (usuario.rows.length === 0) {
        return reply.status(401).send({ message: "Usuário ou senha inválidos!", login: false })
    }

    const senhaValida = await bcrypt.compare(body.senha, usuario.rows[0].senha)

    if (senhaValida) {
        const token = servidor.jwt.sign({
            id: usuario.rows[0].id,
            email: usuario.rows[0].email
        })
        reply.status(200).send({ message: "usuario logado", token })
    } else {
        reply.status(401).send({ message: "Usuário ou senha inválidos!", login: false })
    }
})

servidor.put('/usuarios/:id', async (request, reply) => {
    const body = request.body
    const id = request.params.id

    if (!body || !body.nome || !body.email || !body.senha) {
        return reply.status(400).send({ message: "nome, email e senha são obrigatórios!" })
    }

    const usuario = await sql.query('select * from usuario where id = $1', [id])
    if (usuario.rows.length === 0) {
        return reply.status(400).send({ message: "Usuário não existe!" })
    }

    const salt = 10
    const senhaHash = await bcrypt.hash(body.senha, salt)

    await sql.query('UPDATE usuario SET nome = $1, email = $2, senha = $3 WHERE id = $4', [body.nome, body.email, senhaHash, id])
    reply.status(200).send({ message: `usuario ${body.nome} alterado!` })
})

servidor.delete('/usuarios/:id', async (request, reply) => {
    const id = request.params.id
    await sql.query('DELETE FROM usuario where id = $1', [id])
    reply.status(200).send({ message: 'Usuário Deletado!' })
})

servidor.listen({
    port: 3000
})