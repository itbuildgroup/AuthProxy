const getRandomText = (value = 12): string => {
  const text: string[] = [];
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (let i = 0; i < value; i++) text.push(possible.charAt(Math.floor(Math.random() * possible.length)));

  return text.join("");
};

export default getRandomText;
