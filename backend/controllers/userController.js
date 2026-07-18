
import {User} from "../models/userModel.js"
import bcrypt from "bcryptjs"

export const register = async(req,res)=>{
    try {
        const  {firstName,lastName,email,password} = req.body
        if(!firstName || !lastName || !email || !password){
            res.status(400).json({success:false,message:'All fields are required'})
        }
        const user = await User.findOne({email}) 
        if(user){
            res.status(400).json({success:false,message:'user already exists'})
        }
        const hashedPassword = await bcrypt.hash(password,10)
        const newUser = await User.create({
            firstName,
            lastName,
            email,
            password : hashedPassword
        })
        await newUser.save()
        return res.status(201).json({success:true,message:'user registered successfully',user:newUser})
    } catch (error) {
        res.status(500).json({success:false,message:error.message})
    }
}