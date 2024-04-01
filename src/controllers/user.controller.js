import { asyncHandler } from "../utils/asyncHandler.js";

const registerUser = asyncHandler(async (req,res) => {
    res.status(200).json({
        message: "rry1.0 is coding"
    })
})

export {registerUser}