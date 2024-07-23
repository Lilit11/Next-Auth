export interface IUser{
    id:string
    name:string
    surname:string
    login:string
    password:string
}
export type InputUser = Omit <IUser,'id'>
export type PartialUser =Partial <IUser>