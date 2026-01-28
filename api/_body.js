const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
    });
    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });

const getJsonBody = async (req) => {
  if (req.body && typeof req.body === "object") {
    return req.body;
  }
  return readBody(req);
};

module.exports = { getJsonBody };
