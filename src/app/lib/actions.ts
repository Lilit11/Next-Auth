"use server";

import { PartialUser } from "./types";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import { redirect } from "next/navigation";
import { addUser, getLoginCount, getUserByLogin } from "./api";

export const handleSignup = async (prev: unknown, data: FormData) => {
  const passwordPattern =
    /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
  let user: PartialUser = {
    id: nanoid(),
    name: data.get("name") as string,
    surname: data.get("surname") as string,
    login: data.get("login") as string,
    password: data.get("password") as string,
  };

  if (user.login) {
    const matchingLogin = getLoginCount(user.login);
    if (matchingLogin) {
      return {
        message: "Provided Login is already used",
      };
    }
  }
  if (user.password) {
    if (!passwordPattern.test(user.password)) {
      return {
        message:
          "Password must contain at least 6 characters, including at least one letter, one number, and one special character",
      };
    }
    user.password = await bcrypt.hash(user.password, 10);
  }
  const result = addUser(user);
  console.log(result);
  redirect("/login");
};
export const handleLogin = async (prev: unknown, data: FormData) => {
  const login = data.get("login") as string;
  const password = data.get("password") as string;

  if (!login || !password) {
    return {
      message: "Please fill all the fields",
    };
  }

  const foundUser = getUserByLogin(login);
  if (!foundUser) {
    return {
      message: "Invalid Login",
    };
  }

  const result = await bcrypt.compare(password, foundUser.password);
  if (!result) {
    return { message: "Invalid Password"}
  }
  redirect("/profile");
};
