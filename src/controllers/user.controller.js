import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { upload } from "../middlewares/multer.middleware.js";
import mongoose from "mongoose";

const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false});

        return {accessToken,refreshToken}
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating the tokens")
    }
}

const registerUser = asyncHandler(async (req,res) => {
    //get users detailed from frontend (postman) .it depend on his model
    //validation - not empty
    //check if user already exists: username, email
    //check for images ,check for avatar
    //upload them to cloudinary, avatar 
    //create user object - create entry in db 
    //remove password and refresh token field from response
    //check for user creation
    //return res

    const {fullName, email, username, password} = req.body

    if(
        [fullName,email,username,password].some((field) =>
        field?.trim() === "")
    ){
       throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username },{ email }]
    })

    if(existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }

    console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;
    
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length> 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400 , "Avatar file is required")
    }

    const avatar =await uploadOnCloudinary(avatarLocalPath);
    const coverImage =await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar) {
        throw new ApiError(400 , "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500 , "Something went wrong while regestering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
})

const loginUser = asyncHandler( async(req,res) => {
   //req body => data
   //username or email
   //find the user
   //password check
   //generate access and refresh token
   //send cookie

   const {email,username,password} = req.body

   if(!username && !email) {
       throw new ApiError(400, "username or password is required")
   }

   const user = await User.findOne({
       $or: [{username} , {email}]
   })

   if(!user){
       throw new ApiError(404 , "User does not exist");
   }

   const isPasswordValid = await user.isPasswordCorrect(password)

   if(!isPasswordValid){
    throw new ApiError(401 , "Invalid user credentials");
   }

   const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

   const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

   const options = {
       httpOnly: true,
       secure: true
   }

   return res
   .status(200)
   .cookie("accessToken" , accessToken , options)
   .cookie("refreshToken", refreshToken, options)
   .json(
       new ApiResponse(
           200,
           {
               user: loggedInUser, accessToken,
               refreshToken
           },
           "User logged in successfully"
           )
   )
})

const logoutUser = asyncHandler(async(req,res) => {
    User.findByIdAndUpdate(
        //for this process we made a middleware named verifyJWT
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
 
})

const refreshAccessToken = asyncHandler(async(req,res) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

  if(!incomingRefreshToken){
      throw new ApiError(401, "unauthorized request");
  }
  
  try {
    const decodedToken =jwt.verify(incomingRefreshToken , process.env.REFRESH_TOKEN_SECRET)
    //user._id is saved in refresh token
    const user = await User.findById(decodedToken?._id);
  
    if(!user){
      throw new ApiError(401, "Invalid refresh token");
    }
  
    if(incomingRefreshToken !== user?.refreshToken){
      throw new ApiError(401, "Refresh token is expired or used");
    }
  
    const options = {
        httpOnly: true,
        secure: true
    }
  
    const {accessToken,newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
  
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",newRefreshToken,options)
    .json(
        new ApiResponse(
        200,
        {accessToken,refreshToken: newRefreshToken},
        "Access tooken refreshed"
        )
    )
  } catch (error) {
      throw new ApiError(401,error?.message || "Invalid refresh token")
  }
})

const changeCurrentPassword = asyncHandler(async(req,res) => {
    const {oldPassWord, newPassword} = req.body

     const user = await User.findById(req.user?._id) //if user is logged them because of "auth" middleware we can access the user
     const isPasswordCorrect = await user.isPasswordCorrect(oldPassWord)
     
     if(!isPasswordCorrect){
         throw new ApiError(400, "invalid old password")
     }

     user.password = newPassword;
     await user.save({validateBeforeSave: false})

     return res
     .status(200)
     .json(
         new ApiResponse(200,{},"Pasword Changed Successfully")
     )

})

const getCurrentUser = asyncHandler(async(req,res) => {
    return res.status(200).json(new ApiResponse(200,req.user,"current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async(req,res) => {
    const {fullName , email } = req.body

    if(!fullName || !email){
        throw new ApiError(400 , "All fields are required")
    }
    
    //updated user
    const user = await User.findByIdAndUpdate(
        req.user?._id,
         {
             $set: {
           fullName,
           email: email
         }
        } ,
         {new: true}
         ).select("-password")

         return res
         .status(200)
         .json(
             new ApiResponse(200, user, "Account details updated succesfully")
         )
})

const updateUserAvatar = asyncHandler(async(req,res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400 , "Avatar file is missing")
    }

    //TODO:delete old image

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400 , "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new :true} 
        ).select("-password")

        return res
        .status(200)
        .json(
            new ApiResponse(200, user,"Avatar updated successfully")
        )   
})

const updateUserCoverImage = asyncHandler(async(req,res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400 , "Cover Image is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400 , "Error while uploading on cover image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {new :true} 
        ).select("-password")

        return res
        .status(200)
        .json(
            new ApiResponse(200, user,"Cover image updated successfully")
        )
})

const getUserChannelProfile = asyncHandler(async(req,res) => {
   const {username} = req.params

   if(!username?.trim()){
     throw new ApiError(400 , "username is missing")
   }

   const channel = await User.aggregate([
       {
           $match: {
               username: username?.toLowerCase()
           }
       },
       {
           $lookup: {
               from: "subscriptions", //model lowercase and plural
               localField: "_id",
               foreignField: "channel",
               as: "subscribers"
           }
       },
       {
           $lookup: {
               from:"subscriptions",
               localField:"_id",
               foreignField:"subscribers",
               as:"subscribedTo"
           }
       },
       {
           $addFields:{
               subscribersCount:{
                   $size: "$subscribers"
               },
               channelsSubscribedToCount:{
                   $size: "subscribedTo"
               },
               isSubscribed: {
                   $cond: {
                       if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                       then:true,
                       else: false
                   }
               }
           }
       },
       {
           $project: {
               fullName: 1,
               username: 1,
               subscribersCount: 1,
               channelsSubscribedToCount: 1,
               isSubscribed: 1,
               avatar: 1,
               coverImage: 1,
               email: 1
           }
       }
   ])

   if(!channel?.length) {
       throw new ApiError(404, "channel does not exists")
   }

   return res
   .status(200)
   .json(
       new ApiResponse(200, channel[0] , "User channel fetched uccessfully")
   )

})

const getWatchHistory = asyncHandler(async(req,res) => {
   const user = await User.aggregate([
       {
           $match: {
               id:  new mongoose.Types.ObjectId(req.user._id)
           }
       }, 
       {
           $lookup:{
               from: "videos",
               localField: "watchHistory",
               foreignField: "_id",
               as: "watchHistory",
               pipeline: [
                   {
                       $lookup: {
                           from: "users",
                           localField: "videos",
                           foreignField: "_id",
                           as: "owner",
                           pipeline:[
                               {
                                   $project: {
                                       fullName: 1,
                                       user: 1,
                                       avatar: 1
                                   }
                               }
                           ]
                       }
                   },
                   {
                       $addFields:{
                           owner:{
                               $first: "$owner"
                           }
                       }
                   }
               ]
           }
       },
 
   ])

   return res
   .status(200)
   .json(
       new ApiResponse(
           200,
           user[0].watchHistory,
           "watched history fetched successfully"
       )
   )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}