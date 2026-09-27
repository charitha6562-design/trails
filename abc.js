const express=require("express");
const mongoose=require("mongoose");
const joi=require("joi");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const dotenv=require("dotenv");
const app=express();
const port=5001;
dotenv.config();
app.use(express.json());

//mongodb connection
mongoose.connect("mongodb://localhost:27017/student_url")
.then(()=>{
    console.log("mongodb is connected");
})
.catch((error)=>{
    console.log("error connecting to mongodb");
})

//schema
const studentSchema=mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    course:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    }
});

//validate
const validatestudent=joi.object({
    name:joi.string().required(),
    course:joi.string().required(),
    email:joi.string().email().required(),
    password:joi.string().required()

});

//validation middleware
const studentvalidate=(req,res,next) =>{
    const result=validatestudent.validate(req.body);
    const error=result.error
    if(error){
    return res.status(400).json({
        message:error.details[0].message
    });
}
next();

};

//login validation
const loginvalidation = joi.object({
    email: joi.string().email().required(),
    password: joi.string().required()
});

//login middleware
const loginvalidate = (req, res, next) => {
    const result = loginvalidation.validate(req.body);

    if (result.error) {
        return res.status(400).json({
            message: result.error.details[0].message
        });
    }

    next();
};

//authmiddleware
const authMiddleware = (req,res,next) => {
    try {
        const authheader = req.headers.authorization;

        if(!authheader || !authheader.startsWith("Bearer ")){
            return res.status(401).json({
                message:"Token required"
            });
        }

        const token = authheader.split(" ")[1];

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.student = decoded;

        next();
    }
    catch(error) {
        return res.status(401).json({
            message:"Invalid token"
        });
    }
};

//model
const Student=mongoose.model("Student",studentSchema);

//register
app.post("/register",studentvalidate,async(req,res)=>{
    try{
        const hashedpassword=await bcrypt.hash(req.body.password,10);
        const student=new Student({
            ...req.body,
            password:hashedpassword
        });
        await student.save();
        res.json("user registered successfully");

    }
    catch(error){
        res.json({message:error.message});
    }
});

//login api
app.post("/login",loginvalidate,async(req,res)=>{
    try{
        
        const student= await Student.findOne({email:req.body.email});
        if(!student){
          return res.status(404).json({message:"user not found"})
        }

        const ismatch=await bcrypt.compare(
            req.body.password,
            student.password
        );
        
        if(!ismatch){
           return res.json({message:"Invalid password"});
        }
        const token=jwt.sign({id:student._id},
            process.env.JWT_SECRET,
            {expiresIn:"1h"}
        )
        res.json({message:"Login successfull",
            token: token
        })

    }
    catch(error){
        res.json({message:error.message});
    }
});

//postapi
app.post("/student",studentvalidate,async(req,res)=>{
    try{
        const hashedpassword = await bcrypt.hash(req.body.password,10);
        const student=new Student({
    ...req.body,
    password:hashedpassword
});
        res.status(201).json(student);

    }
    catch(error){
        res.status(500).json({message:error.message});
    }

});

//get api
app.get("/student",authMiddleware,async(req,res)=>{
    try{
        const student=await Student.find();
        res.status(200).json(student);
    }
    catch(error){
        res.status(500).json({message:error.message});
    }

});

//get by id
app.get("/student/:id",authMiddleware,async(req,res)=>{
    try{
        const student=await Student.findById(
            req.params.id
        );
        if(!student){
    return res.status(404).json({
        message:"student not found"
    });
}
        res.status(200).json(student)

    }
    catch(error){
        res.status(500).json({message:error.message});
    }

});

//update
app.put("/student/:id",studentvalidate,async(req,res)=>{
    try{
        const updatedstudent = await Student.findByIdAndUpdate(
          req.params.id,
          req.body,
            {new:true}

    );
    if(!updatedstudent){
        return res.json({message:"student not found"});
    }
    res.json(updatedstudent);


    }
    catch(error){
        res.status(500).json({message:error.message});
    }
});

//delete
app.delete("/student/:id",authMiddleware,async(req,res)=>{
    try{
        const deletestudent=await Student.findByIdAndDelete(req.params.id)
        if(!deletestudent){
            return res.json({message:"student not found"});
        }
        res.json(deletestudent);

    }
    catch(error){
        res.status(500).json({message:error.message});
    }

});

app.listen(port,()=>{
    console.log("server is running on port 5001")
});