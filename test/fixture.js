const userInput = "hello";
element.innerHTML = userInput;
eval(userInput);

import { exec } from "node:child_process";
exec(userInput);

spawn(command, { shell: true });

const html = <div dangerouslySetInnerHTML={{ __html: userInput }} />;

const query = "SELECT * FROM users WHERE name = " + userInput;

const token = Math.random();
const tls = { rejectUnauthorized: false };

const object = {};
object.__proto__ = userInput;

const config = { password: "not-a-real-password" };
