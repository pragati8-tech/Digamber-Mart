import mongoose from "mongoose"

 async function connectDB (){
    try {
        console.log(process.env.MONGO_URI);
        await mongoose.connect(`${process.env.MONGO_URI}/DigamberMart`)
        console.log("MongoDB connected successfully");
    } catch (error) {
        console.log("MongoDB connection failed",error);
    }
}

export default connectDB