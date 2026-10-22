// Fills the gallery from /api/files using the <template> cards in index.html
// The current folder is the ?path= query parameter (relative to files/)

const currentPath = new URLSearchParams(location.search).get("path") || "";

function joinPath(folder, name) {
  return folder ? `${folder}/${name}` : name;
}

function folderUrl(path) {
  return path ? `/?${new URLSearchParams({ path })}` : "/";
}

function fileUrl(prefix, path) {
  return prefix + path.split("/").map(encodeURIComponent).join("/");
}

function card(templateId, name) {
  const node = document.getElementById(templateId).content.firstElementChild.cloneNode(true);
  node.querySelector(".filename").textContent = name;
  return node;
}

function folderCard(name, path) {
  const node = card("folder-card", name);
  node.href = folderUrl(path);
  return node;
}

function imageCard(name, path) {
  const node = card("image-card", name);
  const img = node.querySelector("img");
  img.src = fileUrl("/image/", path);
  img.alt = name;
  node.querySelector(".tag").textContent = `${name.split(".").pop().toUpperCase()} · HTTPS`;
  return node;
}

function videoCard(name, path, streamRoot) {
  const node = card("video-card", name);
  const link = node.querySelector("a");
  link.href = link.textContent = streamRoot;
  const video = node.querySelector("video");
  video.addEventListener("error", () => { node.querySelector(".err").hidden = false; });
  video.src = fileUrl(`${streamRoot}video/`, path);
  return node;
}

function showMessage(text) {
  const el = document.getElementById("message");
  el.textContent = text;
  el.hidden = false;
}

function showNav(path) {
  document.getElementById("current").textContent = `files/${path}`;
  if (path) {
    const back = document.getElementById("back");
    back.href = folderUrl(path.split("/").slice(0, -1).join("/"));
    back.hidden = false;
  }
}

async function loadGallery() {
  showNav(currentPath);
  const res = await fetch(`/api/files?${new URLSearchParams({ path: currentPath })}`);
  if (res.status === 401) {
    location.href = "/login";
    return;
  }
  if (!res.ok) {
    showMessage("Folder not found.");
    return;
  }
  const { path, stream_port, folders, files } = await res.json();
  if (!folders.length && !files.length) {
    showMessage("This folder is empty.");
    return;
  }
  const streamRoot = `https://${location.hostname}:${stream_port}/`;
  const grid = document.getElementById("grid");
  for (const name of folders) {
    grid.append(folderCard(name, joinPath(path, name)));
  }
  for (const file of files) {
    const filePath = joinPath(path, file.name);
    grid.append(file.type === "image"
      ? imageCard(file.name, filePath)
      : videoCard(file.name, filePath, streamRoot));
  }
}

// Keeps the session alive while this page is open
async function ping() {
  try {
    const res = await fetch("/api/ping");
    if (res.status === 401) location.href = "/login?error=expired";
  } catch {}
}

loadGallery();
setInterval(ping, 2 * 60 * 1000);
