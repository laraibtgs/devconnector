const express = require(`express`);
const connectDB = require('./config/db');

const app = express();
const PORT = process.env.PORT || 5000;

//CONNCECT DB
connectDB();

//INIT
app.use(express.json({extended: false}));

app.get('/',(req,res)=>{
    res.send("API IS RUNNUNG CORRECTLY...")
})

app.use("/api/users", require("./routes/api/users"));
app.use("/api/posts", require("./routes/api/posts"));
app.use("/api/profile", require("./routes/api/profile"));
app.use("/api/auth", require("./routes/api/auth"));


app.listen(PORT, ()=>{
    console.log(`Server is Started on Port ${PORT}`);
})