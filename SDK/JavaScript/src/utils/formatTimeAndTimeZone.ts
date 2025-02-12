const formatTimeAndTimeZone = (inputDate: number): string => {
  const date = new Date(inputDate * 1000);

  // const year = date.getFullYear();
  // const month = `0${date.getMonth() + 1}`.slice(-2);
  // const day = `0${date.getDate()}`.slice(-2);
  const hours = `0${date.getHours()}`.slice(-2);
  const minutes = `0${date.getMinutes()}`.slice(-2);

  return `${hours}:${minutes}`;
};

export default formatTimeAndTimeZone;
