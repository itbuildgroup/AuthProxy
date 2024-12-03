export const formatDate = (dateTimeString: string): string => {
  const date: Date = new Date(dateTimeString);

  // Получение компонентов даты
  const year: number = date.getUTCFullYear();
  const month: number = date.getUTCMonth() + 1; // Месяцы начинаются с 0, поэтому добавляем 1
  const day: number = date.getUTCDate();

  // Форматирование даты
  const formattedYear: string = year.toString();
  const formattedMonth: string = month < 10 ? `0${month}` : month.toString();
  const formattedDay: string = day < 10 ? `0${day}` : day.toString();

  return `${formattedDay}.${formattedMonth}.${formattedYear}`;
};

export const formatDateNumber = (inputDate: number) => {
  const date = new Date(inputDate * 1000);

  const year = date.getFullYear();
  const month = `0${date.getMonth() + 1}`.slice(-2);
  const day = `0${date.getDate()}`.slice(-2);
  const hours = `0${date.getHours()}`.slice(-2);
  const minutes = `0${date.getMinutes()}`.slice(-2);

  return `${day}/${month}/${year} ${hours}:${minutes}`;
};
