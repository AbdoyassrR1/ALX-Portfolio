const headerElement = document.createElement("template");
headerElement.innerHTML = `
<header class="animate__animated animate__backInLeft">
  <div class="logo">
    <h1>
      <a href="/">Task Management</a>
    </h1>
  </div>
  <nav>
    <ul id="nav" class="nav">
    <li><a href="./sign-in.html" class="sign-in" id="sign-in">Sign in</a></li>
    <li><a href="./sign-up.html" class="sign-up" id="sign-up">Sign up</a></li>
    </ul>
  </nav>
  <div class="user" id="user">
    <a href="./profile.html" class="profile">
      <span>
        <i class="bi bi-person profile-icon"></i>
      </span>
      Profile
    </a>
    <button type="button" id="btn-sign-out" class="btn-sign-out">
      <i class="bi bi-arrow-clockwise" id="reload-icon"></i>
      Sign Out
    </button>
  </div>
</header>
`;

class Header extends HTMLElement {
  connectedCallback() {
    this.innerHTML = headerElement.innerHTML;
  }
}

customElements.define("header-component", Header);
