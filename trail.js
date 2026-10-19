const express=require("express");
const mongoose=require("mongoose");
const bcrypt=require("bcrypt");
const joi=require("joi");
const jwt=require("jsonwebtoken");
const dotenv=require("dotenv");
dotenv.config();
const port=4006;
const app = express();
app.use(express.json());

//mongodb connection
mongoose.connect("mongodb://127.0.0.1:27017/student_url")
.then(()=>{
    console.log("mongodb connected")
})
.catch((error)=>{
    console.log("error connecting to mongodb")
});

//userschema
const userSchema=new mongoose.Schema({
    name:{
        type:String,required:true
    },
    course:{
        type:String,required:true
    },
    email:{
        type:String,required:true,unique:true
    },
    password: {
        type: String, required: true
    },
    role:{
        type:String,
        enum:["user","admin"],
        default:"user"
    }
});

//model
const User=mongoose.model("User",userSchema);

// Card schema
const cardSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true
        },
        description: {
            type: String,
            required: true,
            trim: true
        },
        status: {
            type: String,
            enum: ["active", "inactive", "deleted"],
            default: "active"
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        updatedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        }
        
    },
    { timestamps: true }
);

// Card model
const Card = mongoose.model("Card", cardSchema);


//validation
const validateuser=joi.object({
    name:joi.string().required(),
    course:joi.string().required(),
    email:joi.string().email().required(),
    password:joi.string().required(),
    role:joi.string().valid("user", "admin").default("user")
})

//validation middleware
const uservalidation=(req,res,next)=>{
const result=validateuser.validate(req.body);
const error=result.error;
if(error){
    return res.status(400).json({message:error.details[0].message})
}
next();
};

//register validation
const registervalidation=joi.object({
    name:joi.string().required(),
    course:joi.string().required(),
    email:joi.string().email().required(),
    password:joi.string().required()
});
//registervalidation middleware
const validateregister=(req,res,next)=>{
    const result=registervalidation.validate(req.body);
    const error=result.error;
    if(error){
        return res.status(400).json({message:error.details[0].message})
    }
    next();
};

//login validation
const loginvalidation=joi.object({
    email:joi.string().email().required(),
    password:joi.string().required()
});

//middleware
const validatelogin=(req,res,next)=>{
    const result=loginvalidation.validate(req.body);
    const error=result.error;
    if(error){
        return res.status(400).json({message:error.details[0].message})
    }
    next();
};


//register
app.post("/register",validateregister,async(req,res)=>{
    try{
        const hashedpassword=await bcrypt.hash(req.body.password,10);
        const user=new User({
            ...req.body,
            password:hashedpassword
    });
        await user.save();
        res.json({message:"user registered successfully"})

    }
    catch(error){
        res.status(500).json({message:error.message});
    }
});

//login
app.post("/login",validatelogin,async(req,res)=>{
    try{
        const user=await User.findOne({email:req.body.email});
        if(!user){
            return res.status(404).json({message:"user not found"})
        }
        const ismatch=await bcrypt.compare(
            req.body.password,
            user.password
        );
        if(!ismatch){
            return res.status(401).json({message:"Invalid Password"})
        }
        const token=jwt.sign({id:user._id,role: user.role},process.env.JWT_SECRET,{expiresIn:"24h"})
         res.json({user,message:"login successfull",
            token:token});
    }
    catch(error){
        res.status(500).json({message:error.message});
    }
})

//authmiddleware
const authmiddleware=(req,res,next)=>{
    try{
        const authheader=req.headers.authorization;
        if(!authheader || !authheader.startsWith("Bearer ")){
            return res.status(401).json({message:"token required"})
        }

        const token=authheader.split(" ")[1];
        const decoded=jwt.verify(
            token,process.env.JWT_SECRET
        );
        req.user=decoded;
        next();

    }
catch(error){
        res.status(401).json({message:error.message});
    }
};

//adminmiddlware

const adminMiddleware=(req,res,next)=>{
    if(req.user.role !== "admin"){
        return res.status(403).json({message:"Admin access required"});
    }
    next();
};

//routes
app.post("/user",uservalidation,authmiddleware,async(req,res)=>{
    try{
        const user=new User(req.body);
        await user.save();
        res.json(user);

    }
    catch(error){
        res.status(500).json({message:error.message});
    }
});

//get api
app.get("/user",authmiddleware,async (req, res) => {
    try {
        const users = await User.find().select("-password");

        res.status(200).json(users);
    } 
    catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
});
//put
app.put("/user/:id",uservalidation,authmiddleware,async(req,res)=>{
    try{
        const updateduser=await User.findByIdAndUpdate(
            req.params.id,
            req.body,
            {new:true}
        );
       res.json(updateduser)

    }
    catch(error){
        res.status(500).json({message:error.message});
    }
});

//delete
app.delete("/user/:id",authmiddleware,adminMiddleware,async(req,res)=>{
    try{
        const userdeleted=await User.findByIdAndDelete(req.params.id);
res.json(userdeleted)
    }
    catch(error){
        res.status(500).json({message:error.message});
    }
});


/* CREATE CARD */
app.post("/cards", authmiddleware, async (req, res) => {
    try {
        const { name, description } = req.body;

        
if (!name || !description) {
    return res.status(400).json({
        message: !name && !description
            ? "Name and description are required"
            : !name
                ? "Name is required"
                : "Description is required"
    });
}
        const card = await Card.create({
            name,
            description,
            createdBy: req.user.id
        });

        const result = await Card.findById(card._id)
            .populate("createdBy", "name");

        res.status(201).json({
            message: "Card created successfully",
            card: result
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


/* GET ALL CARDS */
app.get("/cards", authmiddleware, async (req, res) => {
    try {
        const cards = await Card.find({"status":"active"})
            .populate("createdBy", "name")
            .populate("updatedBy", "name");

        res.status(200).json(cards);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


/* GET CARD BY ID */
app.get("/cards/:id", authmiddleware, async (req, res) => {
    try {
        const card = await Card.findOne({ _id: req.params.id , status: "active"})
            .populate("createdBy", "name")
            .populate("updatedBy", "name");

        if (!card) {
            return res.status(404).json({
                message: "Card not found"
            });
        }

        res.status(200).json(card);

    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
});

/* UPDATE CARD */
app.put("/cards/:id", authmiddleware, async (req, res) => {
    try {
        // Step 1: Check whether ID is provided
        if (!req.params.id) {
            return res.status(400).json({
                message: "Card ID is required"
            });
        }

        // Step 2: Get fields from request body
        const { name, description, status } = req.body;

        // Step 3: Check whether both name and description are missing
        if (
            name === undefined &&
            description === undefined &&
            status === undefined
        ) {
            return res.status(400).json({
                message: "Provide a field to update"
            });
        }

        // Step 4: Validate name if provided
        if (name !== undefined && !name.trim()) {
            return res.status(400).json({
                message: "Name is required"
            });
        }

        // Step 5: Validate description if provided
        if (description !== undefined && !description.trim()) {
            return res.status(400).json({
                message: "Description is required"
            });
        }

        // Step 6: Store fields that need updating
        const updates = {};

        if (name !== undefined) {
            updates.name = name;
        }

        if (description !== undefined) {
            updates.description = description;
        }

        if (status !== undefined) {
            updates.status = status;
        }

        // Step 7: Find and update the card
        const card = await Card.findOneAndUpdate(
            {
                _id: req.params.id,
                status: { $ne: "deleted" }
            },
            {
                $set: {
                    ...updates,
                    updatedBy: req.user.id
                }
            },
            {
                new: true,
                runValidators: true
            }
        )
            .populate("createdBy", "name")
            .populate("updatedBy", "name");

        // Step 8: Check whether the card exists
        if (!card) {
            return res.status(404).json({
                message: "Card not found or already deleted"
            });
        }

        // Step 9: Send the updated card
        res.status(200).json({
            message: "Card updated successfully",
            card
        });

    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
});


/* SOFT DELETE CARD */

app.delete("/cards/:id", authmiddleware, async (req, res) => {
    try {
        const card = await Card.findOneAndUpdate(
            {
                _id: req.params.id,
                status: { $ne: "deleted" }
            },
            {
                $set: {
                    status: "deleted",
                    updatedBy: req.user.id
                }
            },
            {
                new: true,
                runValidators: true
            }
        )
            .populate("createdBy", "name")
            .populate("updatedBy", "name");

        if (!card) {
            return res.status(404).json({
                message: "Card not found or already deleted"
            });
        }

        res.status(200).json({
            message: "Card deleted successfully",
            card: card
        });

    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
});
app.listen(port,()=>{
    console.log(`server is running on ${port}`)
})