console.log("Pragati");
import express from "express"
import connectDB from "./database/db.js"
import "dotenv/config"
const app = express()
const PORT = process.env.PORT || 5555

app.listen(PORT, () => {
    connectDB()
    console.log(`Server is listening at port ${PORT}`)
})