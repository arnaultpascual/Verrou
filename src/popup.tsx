/* @refresh reload */
import { render } from "solid-js/web";
import { PopupApp } from "./features/quick-access/PopupApp";
import "./styles/variables.css";
import "./styles/reset.css";
import "./styles/global.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Root element not found");
}

render(() => <PopupApp />, root);
