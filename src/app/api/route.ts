import { getAllUsers } from "../lib/api"

export function  GET() {
    const users = getAllUsers()
    return Response.json({users})
}